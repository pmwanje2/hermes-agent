"""Regression tests for the t_107752ba dispatcher incident (2026-08-18).

Two defects, one card:

* Defect A — ``detect_crashed_workers`` keys the launch-window grace off
  ``tasks.started_at`` (first claim ever, ``COALESCE``-sticky). After a
  card has been alive >30s, a *new* run can be reaped immediately by a
  second dispatch entry point (``hermes kanban dispatch``, dashboard
  ``/dispatch``, or the next gateway tick). The board-scoped
  ``.dispatch.lock`` only serialises one tick; it is released before the
  spawned worker has settled, so it cannot prevent this.

* Defect B — an ``unknown`` death (``pid N not alive`` — this process did
  not reap the child, typical of a worker spawned by another dispatcher
  or killed by ``reclaim_task``) increments ``consecutive_failures`` the
  same way a real crash does, so two infra-kills trip ``gave_up`` and
  page the operator for a healthy card.
"""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_cli import kanban_db as kb


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_KANBAN_HOME", str(home))
    # Production default (30s). These tests exist to prove the grace is
    # per-run, so they must NOT pin the env to 0 the way the legacy
    # crash-detection suite does.
    monkeypatch.delenv("HERMES_KANBAN_CRASH_GRACE_SECONDS", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    db_path = kb.kanban_db_path(board="default")
    kb._INITIALIZED_PATHS.discard(str(db_path.resolve()))
    kb.init_db()
    return home


@pytest.fixture
def conn(kanban_home):
    with kb.connect() as c:
        yield c


def _host() -> str:
    return kb._claimer_id().split(":", 1)[0]


def _age_first_start(conn, task_id: str, seconds: int = 120) -> None:
    """Make ``tasks.started_at`` look like the first claim was long ago.

    Mirrors a card that has already been through one or more runs — the
    exact shape of t_107752ba when run 9 died at 20s.
    """
    aged = int(time.time()) - seconds
    conn.execute("UPDATE tasks SET started_at = ? WHERE id = ?", (aged, task_id))
    conn.commit()


def test_overlapping_dispatch_once_only_one_claimer_wins(
    conn, all_assignees_spawnable,
):
    """Two dispatch entry points, one ready card: the lock lets only one tick write.

    This is the #35240 contract. It already holds — kept here so the
    incident suite documents that the existing lock is *not* the missing
    piece. The bug is what happens *after* the winner releases the lock
    (see ``test_second_dispatch_once_does_not_steal_fresh_worker``).
    """
    kb.create_task(conn, title="one-card", assignee="worker")
    db_path = kb.kanban_db_path(board="default")
    spawned: list[str] = []

    def spy_spawn(task, workspace, board=None):
        spawned.append(task.id)
        return 4242

    with kb._dispatch_tick_lock(db_path) as held:
        assert held is True
        # Second entry point (CLI / dashboard) while the gateway tick
        # still holds the board lock — must skip, not share the conn.
        other = kb.connect()
        try:
            result = kb.dispatch_once(other, spawn_fn=spy_spawn)
        finally:
            other.close()

    assert result.skipped_locked is True
    assert result.spawned == []
    assert spawned == []


def test_second_dispatch_does_not_reap_fresh_retry_after_first_start_aged(
    conn, monkeypatch,
):
    """Sequential second entry point must honour per-run launch grace.

    Incident shape (t_107752ba run 9):
      * card first-claimed minutes earlier (``tasks.started_at`` stale)
      * a *new* run is only ~20s old
      * a second ``dispatch_once`` / ``detect_crashed_workers`` sees
        ``_pid_alive=False`` (worker spawned by another process, or
        mid-kill) and today reaps it because grace used the first start.

    Before the fix this test FAILS: the young retry is in ``crashed``.
    """
    tid = kb.create_task(conn, title="retry", assignee="worker")
    host = _host()

    # First attempt — ages the sticky tasks.started_at.
    assert kb.claim_task(conn, tid, claimer=f"{host}:old") is not None
    _age_first_start(conn, tid, 180)
    assert kb.reclaim_task(conn, tid, signal_fn=lambda *_: None) is True

    # Fresh retry, well inside the 30s launch window of *this* run.
    assert kb.claim_task(conn, tid, claimer=f"{host}:new") is not None
    kb._set_worker_pid(conn, tid, 3161610)
    monkeypatch.setattr(kb, "_pid_alive", lambda _pid: False)

    crashed = kb.detect_crashed_workers(conn)
    assert tid not in crashed, (
        "a run younger than the launch grace must not be reaped just "
        "because tasks.started_at (first claim) is old"
    )
    task = kb.get_task(conn, tid)
    assert task.status == "running"
    assert task.worker_pid == 3161610
    assert task.consecutive_failures == 0


def test_second_dispatch_once_does_not_steal_fresh_worker(
    conn, all_assignees_spawnable, monkeypatch,
):
    """Two dispatch entry points on one card, lock released between them.

    Tick A (gateway) claims+spawns and drops the lock. Tick B (manual
    ``hermes kanban dispatch``) then runs a full ``dispatch_once``. With
    the first-start grace leak, B's ``detect_crashed_workers`` reaps A's
    young worker and B re-claims under a new lock identity.
    """
    tid = kb.create_task(conn, title="steal", assignee="worker")

    first = kb.dispatch_once(conn, spawn_fn=lambda *a, **k: 3148455)
    assert any(row[0] == tid for row in first.spawned)
    _age_first_start(conn, tid, 180)

    monkeypatch.setattr(kb, "_pid_alive", lambda _pid: False)
    stolen: list[int] = []

    def _second_spawn(task, workspace, board=None):
        stolen.append(3161610)
        return 3161610

    second = kb.dispatch_once(conn, spawn_fn=_second_spawn)
    assert tid not in second.crashed, (
        "second dispatch entry point reaped a worker still inside its "
        "per-run launch grace"
    )
    assert stolen == [], "second entry point must not re-claim the live card"
    task = kb.get_task(conn, tid)
    assert task.status == "running"
    assert task.worker_pid == 3148455


def test_unknown_external_death_does_not_consume_failure_budget(
    conn, monkeypatch,
):
    """``pid N not alive`` (no reap registry) is an infra-kill, not a task error.

    t_107752ba: both counted failures were ``unknown`` deaths after a
    manual reclaim killed the previous worker. Those must not trip
    ``gave_up`` at ``failure_limit=2``. A real ``nonzero_exit`` still
    counts — that is a different test.
    """
    monkeypatch.setenv("HERMES_KANBAN_CRASH_GRACE_SECONDS", "0")
    tid = kb.create_task(conn, title="infra", assignee="worker")
    host = _host()
    monkeypatch.setattr(kb, "_pid_alive", lambda _pid: False)

    for i, pid in enumerate((3161610, 3164511)):
        assert kb.claim_task(conn, tid, claimer=f"{host}:w{i}") is not None
        kb._set_worker_pid(conn, tid, pid)
        # Deliberately do NOT call _record_worker_exit — unknown / external.
        crashed = kb.detect_crashed_workers(conn)
        assert tid in crashed
        task = kb.get_task(conn, tid)
        assert task.status == "ready", (
            f"unknown death {i + 1} must requeue, not block; got {task.status}"
        )
        assert task.consecutive_failures == 0, (
            "externally-terminated / unreaped death must not increment "
            f"consecutive_failures (got {task.consecutive_failures})"
        )
        gave_up = [e for e in kb.list_events(conn, tid) if e.kind == "gave_up"]
        assert gave_up == [], "infra-kills must not emit gave_up"


def test_nonzero_exit_still_counts_toward_gave_up(conn, monkeypatch):
    """A reaped non-zero exit is a real task failure and still trips the breaker."""
    monkeypatch.setenv("HERMES_KANBAN_CRASH_GRACE_SECONDS", "0")
    tid = kb.create_task(conn, title="real-crash", assignee="worker")
    host = _host()
    monkeypatch.setattr(kb, "_pid_alive", lambda _pid: False)

    for i, pid in enumerate((88001, 88002)):
        assert kb.claim_task(conn, tid, claimer=f"{host}:c{i}") is not None
        kb._set_worker_pid(conn, tid, pid)
        kb._record_worker_exit(pid, 1 << 8)  # WEXITSTATUS == 1
        kb.detect_crashed_workers(conn)

    task = kb.get_task(conn, tid)
    assert task.status == "blocked"
    assert task.consecutive_failures >= 2
    gave_up = [e for e in kb.list_events(conn, tid) if e.kind == "gave_up"]
    assert len(gave_up) == 1
    assert (gave_up[0].payload or {}).get("trigger_outcome") == "crashed"


def test_gave_up_alert_does_not_say_spawn_failures_for_a_crash():
    """Operator-facing copy must not call a pid-gone crash a spawn failure."""
    from tui_gateway.server import _format_kanban_event_text

    ev = SimpleNamespace(
        kind="gave_up",
        payload={
            "trigger_outcome": "crashed",
            "error": "pid 3164511 not alive",
            "failures": 2,
        },
    )
    task = SimpleNamespace(title="verify", assignee="maximus-verifier", result=None)
    text = _format_kanban_event_text(
        {"task_id": "t_107752ba"}, task, ev, "ci-failures",
    )
    assert text is not None
    assert "spawn failures" not in text.lower()
    assert "pid 3164511 not alive" in text
    assert "gave up" in text.lower()
