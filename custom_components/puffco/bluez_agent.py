"""Temporary BlueZ pairing agent used while bonding a Peak on a local adapter.

Why this exists
---------------
BlueZ only marks an adapter *bondable* when a default ``org.bluez.Agent1`` is
registered (unless ``AlwaysPairable=true`` is set in ``main.conf``, which Home
Assistant OS does not set). With no agent the kernel answers the Peak's SMP
Security Request with "Pairing Not Supported" and sends Pairing Requests
without the bonding flag, so:

* the PUP app-version read (which needs an encrypted link) never completes, and
* ``Device1.Pair`` fails within ~100 ms with ``AuthenticationFailed``.

macOS works because CoreBluetooth shows its own pairing prompt. Here we register
a short-lived auto-accept agent, request it as the default (which makes the
adapter bondable), run the bond attempt, then unregister it again.

Scope and safety
----------------
* Linux + local BlueZ adapter only (an ESPHome proxy has no BlueZ device path).
* Only requests for the Peak's own BlueZ device path are accepted; anything
  else that tries to pair during the window is rejected.
* Every failure is logged and swallowed: without D-Bus the integration behaves
  exactly as before.

Deliberately no ``from __future__ import annotations``: dbus-fast reads the
D-Bus signatures from the method annotations.
"""

import asyncio
import collections
import contextlib
import logging
import sys
from collections.abc import AsyncIterator
from typing import Any

_LOGGER = logging.getLogger(__name__)

try:
    from dbus_fast import BusType, Message, MessageType
    from dbus_fast.aio import MessageBus
    from dbus_fast.errors import DBusError
    from dbus_fast.service import ServiceInterface, method

    _HAVE_DBUS_FAST = True
except ImportError:  # pragma: no cover - non-Linux dev boxes
    _HAVE_DBUS_FAST = False

BLUEZ_SERVICE = "org.bluez"
AGENT_MANAGER_PATH = "/org/bluez"
AGENT_MANAGER_IFACE = "org.bluez.AgentManager1"
AGENT_PATH = "/org/homeassistant/puffco/pairing_agent"
# KeyboardDisplay lets BlueZ pick Just Works when the Peak has no IO and
# numeric comparison (auto-confirmed below) if it ever advertises a display.
AGENT_CAPABILITY = "KeyboardDisplay"
DBUS_TIMEOUT_S = 5.0
_REJECTED = "org.bluez.Error.Rejected"


def bluez_device_path(client: Any, ble_device: Any = None) -> str | None:
    """Return the BlueZ object path for a locally connected device, else None.

    None means "not a local BlueZ adapter" (ESPHome proxy, macOS, Windows), so
    no agent is registered.
    """
    if not sys.platform.startswith("linux"):
        return None
    candidates: list[Any] = []
    backend = getattr(client, "_backend", None)
    candidates.append(getattr(backend, "_device_path", None))
    details = getattr(ble_device, "details", None)
    if isinstance(details, dict):
        candidates.append(details.get("path"))
    for path in candidates:
        if (
            isinstance(path, str)
            and path.startswith("/org/bluez/")
            and "/dev_" in path
        ):
            return path
    return None


if _HAVE_DBUS_FAST:

    class _AutoAcceptAgent(ServiceInterface):
        """org.bluez.Agent1 that accepts only the allowed device paths."""

        def __init__(self, registry: "_AgentRegistry") -> None:
            super().__init__("org.bluez.Agent1")
            self._registry = registry

        def _check(self, device: str, what: str) -> None:
            if self._registry.is_allowed(device):
                _LOGGER.info("BlueZ agent: %s for %s -> accept", what, device)
                return
            _LOGGER.warning("BlueZ agent: %s for %s -> reject (not a Peak)", what, device)
            raise DBusError(_REJECTED, "Not a device this agent is pairing")

        @method()
        def Release(self):  # noqa: N802 - D-Bus member name
            _LOGGER.debug("BlueZ agent: released by bluetoothd")

        @method()
        def RequestPinCode(self, device: "o") -> "s":  # noqa: N802,F821
            # Legacy BR/EDR PIN; the Peak is LE-only.
            _LOGGER.warning("BlueZ agent: RequestPinCode for %s -> reject", device)
            raise DBusError(_REJECTED, "PIN entry not supported")

        @method()
        def DisplayPinCode(self, device: "o", pincode: "s"):  # noqa: N802,F821
            _LOGGER.info("BlueZ agent: DisplayPinCode %s for %s", pincode, device)

        @method()
        def RequestPasskey(self, device: "o") -> "u":  # noqa: N802,F821
            # We cannot know a passkey the Peak would display; fail fast.
            _LOGGER.warning("BlueZ agent: RequestPasskey for %s -> reject", device)
            raise DBusError(_REJECTED, "Passkey entry not supported")

        @method()
        def DisplayPasskey(  # noqa: N802
            self, device: "o", passkey: "u", entered: "q"  # noqa: F821
        ):
            _LOGGER.info(
                "BlueZ agent: DisplayPasskey %06d for %s (entered %s)",
                passkey,
                device,
                entered,
            )

        @method()
        def RequestConfirmation(self, device: "o", passkey: "u"):  # noqa: N802,F821
            self._check(device, f"RequestConfirmation {passkey:06d}")

        @method()
        def RequestAuthorization(self, device: "o"):  # noqa: N802,F821
            self._check(device, "RequestAuthorization")

        @method()
        def AuthorizeService(self, device: "o", uuid: "s"):  # noqa: N802,F821
            self._check(device, f"AuthorizeService {uuid}")

        @method()
        def Cancel(self):  # noqa: N802
            _LOGGER.info("BlueZ agent: pairing request cancelled by bluetoothd")


class _AgentRegistry:
    """One shared agent per HA process, ref-counted across Peaks."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._allowed: collections.Counter[str] = collections.Counter()
        self._bus: Any = None

    def is_allowed(self, device_path: str) -> bool:
        return self._allowed.get(device_path, 0) > 0

    @staticmethod
    async def _call(bus: Any, member: str, signature: str, body: list) -> Any:
        reply = await asyncio.wait_for(
            bus.call(
                Message(
                    destination=BLUEZ_SERVICE,
                    path=AGENT_MANAGER_PATH,
                    interface=AGENT_MANAGER_IFACE,
                    member=member,
                    signature=signature,
                    body=body,
                )
            ),
            timeout=DBUS_TIMEOUT_S,
        )
        if reply.message_type == MessageType.ERROR:
            raise RuntimeError(f"{member}: {reply.error_name} {reply.body}")
        return reply

    @staticmethod
    async def _get_prop(bus: Any, path: str, iface: str, name: str) -> Any:
        try:
            reply = await asyncio.wait_for(
                bus.call(
                    Message(
                        destination=BLUEZ_SERVICE,
                        path=path,
                        interface="org.freedesktop.DBus.Properties",
                        member="Get",
                        signature="ss",
                        body=[iface, name],
                    )
                ),
                timeout=DBUS_TIMEOUT_S,
            )
        except Exception:  # noqa: BLE001 - diagnostics only
            return None
        if reply.message_type == MessageType.ERROR or not reply.body:
            return None
        return getattr(reply.body[0], "value", None)

    async def acquire(self, device_path: str) -> bool:
        async with self._lock:
            self._allowed[device_path] += 1
            if self._bus is not None:
                return True
            bus = None
            try:
                bus = await asyncio.wait_for(
                    MessageBus(bus_type=BusType.SYSTEM).connect(),
                    timeout=DBUS_TIMEOUT_S,
                )
                bus.export(AGENT_PATH, _AutoAcceptAgent(self))
                await self._call(
                    bus, "RegisterAgent", "os", [AGENT_PATH, AGENT_CAPABILITY]
                )
                # Becoming the *default* agent is what flips the adapter to
                # bondable when AlwaysPairable is off (BlueZ adapter.c).
                await self._call(bus, "RequestDefaultAgent", "o", [AGENT_PATH])
            except Exception as err:  # noqa: BLE001 - never fatal
                _LOGGER.warning(
                    "Could not register BlueZ pairing agent (continuing without): %s",
                    err,
                )
                self._allowed[device_path] -= 1
                if bus is not None:
                    with contextlib.suppress(Exception):
                        bus.disconnect()
                return False
            self._bus = bus

        adapter_path = device_path.rsplit("/", 1)[0]
        pairable = await self._get_prop(
            bus, adapter_path, "org.bluez.Adapter1", "Pairable"
        )
        if not pairable:
            # SET_BONDABLE is issued asynchronously by bluetoothd.
            await asyncio.sleep(0.3)
            pairable = await self._get_prop(
                bus, adapter_path, "org.bluez.Adapter1", "Pairable"
            )
        _LOGGER.info(
            "BlueZ pairing agent registered (%s, default) for %s; adapter Pairable=%s",
            AGENT_CAPABILITY,
            device_path,
            pairable,
        )
        return True

    async def release(self, device_path: str) -> None:
        async with self._lock:
            if self._allowed[device_path] > 0:
                self._allowed[device_path] -= 1
            if self._allowed[device_path] <= 0:
                self._allowed.pop(device_path, None)
            bus = self._bus
            if bus is None:
                return
            paired = await self._get_prop(bus, device_path, "org.bluez.Device1", "Paired")
            bonded = await self._get_prop(bus, device_path, "org.bluez.Device1", "Bonded")
            _LOGGER.info(
                "BlueZ bond state for %s after attempt: Paired=%s Bonded=%s",
                device_path,
                paired,
                bonded,
            )
            if any(count > 0 for count in self._allowed.values()):
                return  # another Peak is still bonding
            self._bus = None
            try:
                await self._call(bus, "UnregisterAgent", "o", [AGENT_PATH])
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("UnregisterAgent failed (bus close drops it): %s", err)
            with contextlib.suppress(Exception):
                bus.unexport(AGENT_PATH)
            with contextlib.suppress(Exception):
                bus.disconnect()
            _LOGGER.info("BlueZ pairing agent unregistered")


_REGISTRY = _AgentRegistry()


@contextlib.asynccontextmanager
async def bluez_pairing_agent(device_path: str | None) -> AsyncIterator[bool]:
    """Register an auto-accept agent for ``device_path`` for the block's duration.

    Yields True when the agent is active. Never raises for D-Bus problems.
    """
    acquired = False
    if device_path is not None and _HAVE_DBUS_FAST:
        try:
            acquired = await _REGISTRY.acquire(device_path)
        except Exception as err:  # noqa: BLE001 - never fatal
            _LOGGER.warning("BlueZ pairing agent setup failed: %s", err)
    try:
        yield acquired
    finally:
        if acquired:
            try:
                await _REGISTRY.release(device_path)  # type: ignore[arg-type]
            except Exception as err:  # noqa: BLE001
                _LOGGER.warning("BlueZ pairing agent teardown failed: %s", err)
