"""SSRF e assinatura HMAC dos webhooks de conclusão."""

from __future__ import annotations

import hashlib
import hmac
from unittest.mock import patch

import pytest

from app import db as dbmod
from app.core import callbacks
from app.core.orchestrator import _notify_callback
from app.models import AuditEvent, Engagement, Job, JobStatus


def test_validate_callback_url_rejects_bad_syntax() -> None:
    for bad in (
        "ftp://example.com/hook",
        "https://user:pass@example.com/hook",
        "https:///sem-host",
        "https://example.com:bad/hook",
    ):
        with pytest.raises(ValueError):
            callbacks.validate_callback_url(bad)
    assert callbacks.validate_callback_url("https://example.com/hook") == (
        "https://example.com/hook"
    )


def test_assert_safe_callback_rejects_private_ip(monkeypatch) -> None:
    monkeypatch.setattr(callbacks, "_resolve_ips", lambda host, port: {"127.0.0.1"})
    with pytest.raises(ValueError, match="não público"):
        callbacks.assert_safe_callback_url("http://internal.local/hook")


def test_assert_safe_callback_accepts_public_ip(monkeypatch) -> None:
    monkeypatch.setattr(callbacks, "_resolve_ips", lambda host, port: {"93.184.216.34"})
    assert callbacks.assert_safe_callback_url("https://example.com/hook") == (
        "https://example.com/hook"
    )


def test_encode_callback_signs_body_and_timestamp() -> None:
    body, headers = callbacks.encode_callback({"b": 2, "a": 1}, "segredo")
    assert body == b'{"a":1,"b":2}'
    timestamp = headers["X-Ethoscan-Timestamp"]
    expected = hmac.new(
        b"segredo", timestamp.encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    assert headers["X-Ethoscan-Signature"] == f"sha256={expected}"


def test_encode_callback_without_secret_has_no_signature() -> None:
    _, headers = callbacks.encode_callback({"a": 1}, "")
    assert "X-Ethoscan-Signature" not in headers


def _job_for_callback(db) -> tuple[Engagement, Job]:
    engagement = Engagement(
        name="Hook SSRF", scope_targets=["scanme.nmap.org"], roe_acknowledged=True
    )
    db.add(engagement)
    db.commit()
    db.refresh(engagement)
    job = Job(
        engagement_id=engagement.id,
        status=JobStatus.completed,
        phase="F6",
        progress=100,
        tool_runs={},
        selected_tools=["nmap"],
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return engagement, job


def test_notify_callback_blocks_private_url(client) -> None:
    db = dbmod.SessionLocal()
    try:
        engagement, job = _job_for_callback(db)
        with (
            patch(
                "app.core.orchestrator.get_callback",
                return_value="http://127.0.0.1/hook",
            ),
            patch(
                "app.core.orchestrator.assert_safe_callback_url",
                side_effect=ValueError("IP não público"),
            ),
            patch("app.core.orchestrator.httpx.post") as post,
            patch("app.core.orchestrator.clear_callback") as cleared,
        ):
            _notify_callback(db, job, engagement, "completed")

        post.assert_not_called()
        cleared.assert_called_once_with(job.id)
        actions = {event.action for event in db.query(AuditEvent).all()}
        assert "callback_blocked" in actions
    finally:
        db.close()
