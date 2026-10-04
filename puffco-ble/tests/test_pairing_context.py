"""The host-supplied pairing context must wrap every OS bond attempt."""

from __future__ import annotations

import contextlib

import pytest
from bleak import BleakError

from puffco_ble.ble_client import PuffcoBleakClient
from puffco_ble.constants import PUP_APP_VERSION_CHAR


def _bare_client() -> PuffcoBleakClient:
    """A PuffcoBleakClient without a real Bleak backend."""
    client = object.__new__(PuffcoBleakClient)
    client.pairing_context = None
    client._already_paired = False
    client._skip_explicit_pair = False
    return client


class _Recorder:
    def __init__(self) -> None:
        self.events: list[str] = []

    def factory(self):
        @contextlib.asynccontextmanager
        async def _cm():
            self.events.append("enter")
            try:
                yield True
            finally:
                self.events.append("exit")

        return _cm()


@pytest.fixture
def connected(monkeypatch):
    monkeypatch.setattr(
        PuffcoBleakClient, "is_connected", property(lambda self: True)
    )


async def test_trigger_bond_read_runs_inside_pairing_context(monkeypatch, connected):
    client = _bare_client()
    rec = _Recorder()
    client.pairing_context = rec.factory
    monkeypatch.setattr(client, "_char_available", lambda uuid: uuid == PUP_APP_VERSION_CHAR)

    async def fake_read(char_uuid, *, timeout):
        rec.events.append(f"read:{char_uuid == PUP_APP_VERSION_CHAR}")
        return bytearray(b"\x01")

    monkeypatch.setattr(client, "_read_gatt_char_timed", fake_read)
    await client._trigger_bond(timeout_s=1.0)
    assert rec.events == ["enter", "read:True", "exit"]


async def test_trigger_bond_context_closed_on_timeout(monkeypatch, connected):
    client = _bare_client()
    rec = _Recorder()
    client.pairing_context = rec.factory
    monkeypatch.setattr(client, "_char_available", lambda uuid: uuid == PUP_APP_VERSION_CHAR)

    async def failing_read(char_uuid, *, timeout):
        rec.events.append("read")
        raise BleakError("GATT read timed out")

    monkeypatch.setattr(client, "_read_gatt_char_timed", failing_read)
    await client._trigger_bond(timeout_s=0.05, retry_delay_s=0.01)
    assert rec.events[0] == "enter"
    assert rec.events[-1] == "exit"
    assert "read" in rec.events


async def test_explicit_pair_runs_inside_pairing_context(monkeypatch):
    client = _bare_client()
    rec = _Recorder()
    client.pairing_context = rec.factory

    async def fake_pair(*_a, **_kw):
        rec.events.append("pair")

    monkeypatch.setattr(client, "pair", fake_pair)
    assert await client._ensure_bonded() is True
    assert rec.events == ["enter", "pair", "exit"]


async def test_no_context_and_broken_factory_are_noops(monkeypatch):
    client = _bare_client()
    calls: list[str] = []

    async def fake_pair(*_a, **_kw):
        calls.append("pair")

    monkeypatch.setattr(client, "pair", fake_pair)
    assert await client._ensure_bonded() is True

    client._already_paired = False

    def broken_factory():
        raise RuntimeError("dbus exploded")

    client.pairing_context = broken_factory
    assert await client._ensure_bonded() is True
    assert calls == ["pair", "pair"]
