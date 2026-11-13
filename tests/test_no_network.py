"""Legal-safety proof: Sangop must never open a network connection."""

import socket

import pytest
from conftest import AADHAAR, GITHUB_TOKEN, PAN

import sangop
from sangop.cli import main as cli_main


@pytest.fixture
def no_network(monkeypatch):
    def _blocked(*a, **k):
        raise AssertionError("Sangop attempted a network connection")
    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)


def test_everything_works_offline(no_network, tmp_path):
    sangop.configure(ledger_path=str(tmp_path / "a.db"))

    @sangop.guard(purpose="t", sql_param="q")
    def tool(q: str):
        return {"pan": PAN, "aadhaar": AADHAAR}

    tool("SELECT 1 FROM t LIMIT 1")
    assert sangop.get_ledger().verify()[0]
    (tmp_path / "f.env").write_text(f"TOKEN={GITHUB_TOKEN}\n")
    assert cli_main(["scan", str(tmp_path), "--fail-on", "none"]) == 0
