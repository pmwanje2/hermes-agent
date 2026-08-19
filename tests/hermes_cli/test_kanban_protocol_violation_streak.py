"""Regression: protocol-violation breaker vs interleaved bare crashes.

Live incident (boq-003, 2026-08-19, t_f4c4900b / t_3db7b272 / t_4cc492d0):
the 3-strike violation breaker never tripped because
``_protocol_violation_streak`` ``break``s on any closed run that is not a
recognised violation. The dispatcher records two kinds of ``crashed`` row
on the same 60s tick:

* ``protocol_violation=True`` + ``exit_code`` — counted
* bare ``crashed`` (``pid`` / ``claimer`` / ``retry_status`` only,
  error ``pid N not alive``) — previously reset the streak to 0

Those bare rows are unclassified infra-kills (``_classify_worker_exit``
returned ``unknown``): the recorded PID is gone and this process did not
reap it. They are the other face of the same reap/respawn loop, not a
different failure kind, so they must be skipped the same way
``rate_limited`` already is.

A second, independent defect: ``detect_crashed_workers`` treats a dead
recorded PID as a crash even when the *active run* heartbeated seconds
ago. ``claim_task`` / ``claim_review_task`` already refuse a ``running``
card, so the "duplicate spawn" is not a concurrent claim — it is the
same tick reaping a still-live run and immediately re-claiming it.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_KANBAN_HOME", str(home))
    # Instant reclaim so we can drive the reaper without sleeping out
    # the 30s launch grace. Heartbeat-freshness tests that need the
    # production hold re-enable HERMES_KANBAN_CRASH_HEARTBEAT_FRESH_SECONDS
    # themselves.
    monkeypatch.setenv("HERMES_KANBAN_CRASH_GRACE_SECONDS", "0")
    monkeypatch.setenv("HERMES_KANBAN_CRASH_HEARTBEAT_FRESH_SECONDS", "0")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    db_path = kb.kanban_db_path(board="default")
    kb._INITIALIZED_PATHS.discard(str(db_path.resolve()))
    kb.init_db()
    return home


def _host() -> str:
    return kb._claimer_id().split(":", 1)[0]


def _insert_closed_run(
    conn,
    task_id: str,
    *,
    outcome: str,
    error: str | None,
    metadata: dict | None,
    started_at: int,
    ended_at: int,
) -> int:
    cur = conn.execute(
        "INSERT INTO task_runs (task_id, profile, status, outcome, "
        "error, metadata, started_at, ended_at) "
        "VALUES (?, 'worker', ?, ?, ?, ?, ?, ?)",
        (
            task_id,
            outcome,
            outcome,
            error,
            json.dumps(metadata) if metadata is not None else None,
            started_at,
            ended_at,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def test_interleaved_bare_crash_does_not_reset_violation_streak(kanban_home):
    """Direct walk: violation, bare crash, violation, bare crash still counts 2.

    Acceptance shape from t_69ce312c. A real classified nonzero crash
    (below) must still reset — this test is only about the unclassified
    ``pid N not alive`` row.
    """
    conn = kb.connect()
    try:
        tid = kb.create_task(conn, title="interleaved", assignee="worker")
        now = int(time.time())
        # Newest-first walk, so insert oldest → newest.
        history = (
            # oldest
            (
                "crashed",
                "worker exited cleanly (rc=0) without calling "
                "kanban_complete or kanban_block — protocol violation.",
                {
                    "pid": 11,
                    "claimer": "host:w",
                    "exit_code": 0,
                    "protocol_violation": True,
                    "retry_status": "review",
                },
            ),
            (
                "crashed",
                "pid 12 not alive",
                {"pid": 12, "claimer": "host:w", "retry_status": "review"},
            ),
            (
                "crashed",
                "worker exited cleanly (rc=0) without calling "
                "kanban_complete or kanban_block — protocol violation.",
                {
                    "pid": 13,
                    "claimer": "host:w",
                    "exit_code": 0,
                    "protocol_violation": True,
                    "retry_status": "review",
                },
            ),
            (
                "crashed",
                "pid 14 not alive",
                {"pid": 14, "claimer": "host:w", "retry_status": "review"},
            ),
        )
        for i, (outcome, error, meta) in enumerate(history):
            _insert_closed_run(
                conn,
                tid,
                outcome=outcome,
                error=error,
                metadata=meta,
                started_at=now - 80 + i * 20,
                ended_at=now - 60 + i * 20,
            )

        assert kb._protocol_violation_streak(conn, tid) == 2
    finally:
        conn.close()


def test_classified_nonzero_crash_still_resets_violation_streak(kanban_home):
    """A real reaped nonzero exit is a different failure kind — it breaks.

    ``consecutive`` would be meaningless if every crash were skipped.
    The live defect is the *unclassified* row, not a WEXITSTATUS!=0.
    """
    conn = kb.connect()
    try:
        tid = kb.create_task(conn, title="classified", assignee="worker")
        now = int(time.time())
        _insert_closed_run(
            conn,
            tid,
            outcome="crashed",
            error="worker exited cleanly (rc=0) without calling "
            "kanban_complete or kanban_block — protocol violation.",
            metadata={
                "pid": 21,
                "claimer": "host:w",
                "exit_code": 0,
                "protocol_violation": True,
                "retry_status": "ready",
            },
            started_at=now - 40,
            ended_at=now - 30,
        )
        _insert_closed_run(
            conn,
            tid,
            outcome="crashed",
            error="pid 22 exited with code 1",
            metadata={
                "pid": 22,
                "claimer": "host:w",
                "exit_kind": "nonzero_exit",
                "exit_code": 1,
                "retry_status": "ready",
            },
            started_at=now - 20,
            ended_at=now - 10,
        )
        _insert_closed_run(
            conn,
            tid,
            outcome="crashed",
            error="worker exited cleanly (rc=0) without calling "
            "kanban_complete or kanban_block — protocol violation.",
            metadata={
                "pid": 23,
                "claimer": "host:w",
                "exit_code": 0,
                "protocol_violation": True,
                "retry_status": "ready",
            },
            started_at=now - 5,
            ended_at=now,
        )
        assert kb._protocol_violation_streak(conn, tid) == 1
    finally:
        conn.close()


def _drive_protocol_violation(conn, tid, fake_pid):
    host = _host()
    claimed = kb.claim_task(conn, tid, claimer=f"{host}:mock")
    assert claimed is not None
    kb._set_worker_pid(conn, tid, fake_pid)
    kb._record_worker_exit(fake_pid, 0)
    original = kb._pid_alive
    kb._pid_alive = lambda _p: False
    try:
        return kb.detect_crashed_workers(conn)
    finally:
        kb._pid_alive = original


def _drive_bare_unknown_crash(conn, tid, fake_pid):
    """Reap with no wait-status in the registry — the live bare-crash row."""
    host = _host()
    claimed = kb.claim_task(conn, tid, claimer=f"{host}:mock")
    assert claimed is not None
    kb._set_worker_pid(conn, tid, fake_pid)
    original = kb._pid_alive
    kb._pid_alive = lambda _p: False
    try:
        return kb.detect_crashed_workers(conn)
    finally:
        kb._pid_alive = original


def test_interleaved_bare_crashes_still_trip_violation_breaker(kanban_home):
    """violation, bare, violation, bare, violation → blocked at the limit.

    Pre-fix the bare ``unknown`` row reset the streak, so this sequence
    never reached 3 and respawned without bound.
    """
    conn = kb.connect()
    try:
        tid = kb.create_task(conn, title="breaker", assignee="worker")

        _drive_protocol_violation(conn, tid, 88001)
        task = kb.get_task(conn, tid)
        assert task is not None
        assert task.status == "ready"
        assert task.consecutive_failures == 0

        _drive_bare_unknown_crash(conn, tid, 88002)
        task = kb.get_task(conn, tid)
        assert task is not None
        assert task.status == "ready"
        assert task.consecutive_failures == 0

        _drive_protocol_violation(conn, tid, 88003)
        task = kb.get_task(conn, tid)
        assert task is not None
        assert task.status == "ready", (
            "second violation interleaved with a bare crash must still retry"
        )

        _drive_bare_unknown_crash(conn, tid, 88004)
        task = kb.get_task(conn, tid)
        assert task is not None
        assert task.status == "ready"

        _drive_protocol_violation(conn, tid, 88005)
        task = kb.get_task(conn, tid)
        assert task is not None
        assert task.status == "blocked"
        gave_up = [e for e in kb.list_events(conn, tid) if e.kind == "gave_up"]
        assert len(gave_up) == 1
        assert (gave_up[0].payload or {}).get("protocol_violations") == (
            kb._PROTOCOL_VIOLATION_FAILURE_LIMIT
        )
        assert kb._PROTOCOL_VIOLATION_FAILURE_LIMIT == 3
    finally:
        conn.close()


def test_fresh_run_heartbeat_blocks_dead_pid_reap(kanban_home, monkeypatch):
    """A running card whose active run heartbeated seconds ago is not crashed.

    The recorded PID can be a wrapper that already exited (or a pid the
    dispatcher never reaped). Heartbeat is the liveness signal for the
    *run*; a dead bookkeeping pid must not flip the card back to ready
    so the same tick can spawn a replacement.
    """
    monkeypatch.delenv("HERMES_KANBAN_CRASH_GRACE_SECONDS", raising=False)
    monkeypatch.setenv("HERMES_KANBAN_CRASH_GRACE_SECONDS", "30")
    monkeypatch.setenv("HERMES_KANBAN_CRASH_HEARTBEAT_FRESH_SECONDS", "120")
    conn = kb.connect()
    try:
        tid = kb.create_task(conn, title="live-hb", assignee="worker")
        host = _host()
        assert kb.claim_task(conn, tid, claimer=f"{host}:w") is not None
        kb._set_worker_pid(conn, tid, 3161610)
        assert kb.heartbeat_worker(conn, tid, note="still working")

        # Launch grace has elapsed (first-start / run-start both aged),
        # so only the heartbeat can protect this card.
        aged = int(time.time()) - 120
        conn.execute(
            "UPDATE tasks SET started_at = ? WHERE id = ?", (aged, tid)
        )
        conn.execute(
            "UPDATE task_runs SET started_at = ? WHERE task_id = ? "
            "AND ended_at IS NULL",
            (aged, tid),
        )
        conn.commit()

        monkeypatch.setattr(kb, "_pid_alive", lambda _pid: False)
        crashed = kb.detect_crashed_workers(conn)
        assert tid not in crashed, (
            "fresh last_heartbeat_at must stop detect_crashed_workers "
            "from reaping a run whose recorded pid is already gone"
        )
        task = kb.get_task(conn, tid)
        assert task is not None
        assert task.status == "running"
        assert task.worker_pid == 3161610
    finally:
        conn.close()


def test_stale_heartbeat_still_reaps_dead_pid(kanban_home, monkeypatch):
    """Heartbeat protection is not a forever-hold: a silent dead pid reaps."""
    monkeypatch.setenv("HERMES_KANBAN_CRASH_GRACE_SECONDS", "0")
    conn = kb.connect()
    try:
        tid = kb.create_task(conn, title="stale-hb", assignee="worker")
        host = _host()
        assert kb.claim_task(conn, tid, claimer=f"{host}:w") is not None
        kb._set_worker_pid(conn, tid, 3161611)
        assert kb.heartbeat_worker(conn, tid, note="old")
        stale = int(time.time()) - 10_000
        conn.execute(
            "UPDATE tasks SET last_heartbeat_at = ? WHERE id = ?",
            (stale, tid),
        )
        conn.execute(
            "UPDATE task_runs SET last_heartbeat_at = ? WHERE task_id = ? "
            "AND ended_at IS NULL",
            (stale, tid),
        )
        conn.commit()
        monkeypatch.setattr(kb, "_pid_alive", lambda _pid: False)
        crashed = kb.detect_crashed_workers(conn)
        assert tid in crashed
        task = kb.get_task(conn, tid)
        assert task is not None
        assert task.status == "ready"
    finally:
        conn.close()


def test_dispatch_once_does_not_respawn_heartbeating_run(
    kanban_home, all_assignees_spawnable, monkeypatch
):
    """Same-tick respawn is the live 'duplicate': reap then re-claim.

    Tick records a dead wrapper pid, but the run heartbeated seconds
    ago. The card must stay ``running`` under the original pid — no new
    spawn, no ``crashed`` outcome.
    """
    monkeypatch.setenv("HERMES_KANBAN_CRASH_GRACE_SECONDS", "30")
    monkeypatch.setenv("HERMES_KANBAN_CRASH_HEARTBEAT_FRESH_SECONDS", "120")
    conn = kb.connect()
    try:
        tid = kb.create_task(conn, title="no-dup", assignee="worker")
        first = kb.dispatch_once(conn, spawn_fn=lambda *a, **k: 3148455)
        assert any(row[0] == tid for row in first.spawned)
        assert kb.heartbeat_worker(conn, tid, note="alive")

        aged = int(time.time()) - 120
        conn.execute(
            "UPDATE tasks SET started_at = ? WHERE id = ?", (aged, tid)
        )
        conn.execute(
            "UPDATE task_runs SET started_at = ? WHERE task_id = ? "
            "AND ended_at IS NULL",
            (aged, tid),
        )
        conn.commit()

        monkeypatch.setattr(kb, "_pid_alive", lambda _pid: False)
        stolen: list[int] = []

        def _second_spawn(task, workspace, board=None):
            stolen.append(3161610)
            return 3161610

        second = kb.dispatch_once(conn, spawn_fn=_second_spawn)
        assert tid not in second.crashed
        assert stolen == []
        task = kb.get_task(conn, tid)
        assert task is not None
        assert task.status == "running"
        assert task.worker_pid == 3148455
        outcomes = [
            r["outcome"]
            for r in conn.execute(
                "SELECT outcome FROM task_runs WHERE task_id=?", (tid,)
            ).fetchall()
        ]
        assert "crashed" not in outcomes
    finally:
        conn.close()


def test_sticky_task_heartbeat_does_not_shield_new_run_unknown_death(
    kanban_home, monkeypatch,
):
    """``tasks.last_heartbeat_at`` is first-run sticky; only *this* run counts.

    A retry whose own run has never heartbeated must still reap an
    unclassified dead pid. Shielding it with the previous run's heartbeat
    would recreate the t_107752ba false-alive hold.
    """
    monkeypatch.setenv("HERMES_KANBAN_CRASH_GRACE_SECONDS", "0")
    conn = kb.connect()
    try:
        tid = kb.create_task(conn, title="sticky-hb", assignee="worker")
        host = _host()
        assert kb.claim_task(conn, tid, claimer=f"{host}:old") is not None
        kb._set_worker_pid(conn, tid, 77001)
        assert kb.heartbeat_worker(conn, tid, note="previous run")
        monkeypatch.setattr(kb, "_pid_alive", lambda _pid: False)
        assert tid in kb.detect_crashed_workers(conn)

        assert kb.claim_task(conn, tid, claimer=f"{host}:new") is not None
        kb._set_worker_pid(conn, tid, 77002)
        task = kb.get_task(conn, tid)
        assert task is not None
        assert task.last_heartbeat_at is not None  # leftover on the task row
        run = kb.latest_run(conn, tid)
        assert run is not None
        assert run.last_heartbeat_at is None

        crashed = kb.detect_crashed_workers(conn)
        assert tid in crashed
        task = kb.get_task(conn, tid)
        assert task is not None
        assert task.status == "ready"
    finally:
        conn.close()


def test_fresh_heartbeat_blocks_wrapper_clean_exit_false_violation(
    kanban_home, monkeypatch,
):
    """A wrapper that exits 0 is not a protocol violation if the run ticks.

    ``_default_spawn`` records ``Popen.pid``. If that process is a
    launcher that exits 0 while the grandchild keeps heartbeating, the
    reap registry reports ``clean_exit`` — the same shape as a real
    protocol violation. The run heartbeat is the tie-break.
    """
    monkeypatch.setenv("HERMES_KANBAN_CRASH_GRACE_SECONDS", "0")
    monkeypatch.setenv("HERMES_KANBAN_CRASH_HEARTBEAT_FRESH_SECONDS", "120")
    conn = kb.connect()
    try:
        tid = kb.create_task(conn, title="wrapper-0", assignee="worker")
        host = _host()
        assert kb.claim_task(conn, tid, claimer=f"{host}:w") is not None
        kb._set_worker_pid(conn, tid, 88011)
        kb._record_worker_exit(88011, 0)
        assert kb.heartbeat_worker(conn, tid, note="grandchild alive")
        monkeypatch.setattr(kb, "_pid_alive", lambda _pid: False)
        crashed = kb.detect_crashed_workers(conn)
        assert tid not in crashed
        task = kb.get_task(conn, tid)
        assert task is not None
        assert task.status == "running"
        events = [e.kind for e in kb.list_events(conn, tid)]
        assert "protocol_violation" not in events
    finally:
        conn.close()
