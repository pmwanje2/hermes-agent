"""Card Acceptance Oracle runner — recording only, no enforcement.

Unit tests mock the docker subprocess boundary. Live container tests are
marked ``integration`` (excluded by default addopts) and also require
``CAO_ORACLE_LIVE=1`` so a local ``pytest tests/hermes_cli/test_kanban_oracle.py``
never pulls a 20s docker run by accident.

Run live tests explicitly:

    CAO_ORACLE_LIVE=1 PYTHONPATH=... pytest tests/hermes_cli/test_kanban_oracle.py \\
        -m integration -o addopts= -q
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_cli import kanban_db as kb


LIVE_REPO = Path("/home/paulmwanje/maximus-platform")
LIVE_WORKTREES = Path("/home/paulmwanje/maximus-worktrees")
LIVE_JEST_TARGET = "apps/agent-gateway/tests/unit/telegram/appIdGuard.test.ts"


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


def _init_git_repo(repo: Path) -> str:
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-b", "main", str(repo)],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "oracle@example.com"],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Oracle Test"],
        check=True,
        capture_output=True,
        text=True,
    )
    (repo / "README.md").write_text("hello\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(repo), "add", "README.md"],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "init"],
        check=True,
        capture_output=True,
        text=True,
    )
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return head


def _set_oracle(
    conn: sqlite3.Connection,
    task_id: str,
    *,
    kind: str | None,
    cmd: str | None = None,
    timeout_s: int | None = None,
    image: str | None = None,
    waiver: str | None = None,
    workspace_path: str | None = None,
) -> None:
    with kb.write_txn(conn):
        conn.execute(
            """
            UPDATE tasks
               SET oracle_kind = ?,
                   oracle_cmd = ?,
                   oracle_timeout_s = ?,
                   oracle_image = ?,
                   oracle_waiver_reason = ?,
                   workspace_path = COALESCE(?, workspace_path)
             WHERE id = ?
            """,
            (kind, cmd, timeout_s, image, waiver, workspace_path, task_id),
        )


def _seed_task(
    conn: sqlite3.Connection,
    *,
    kind: str | None,
    cmd: str | None = None,
    workspace_path: str | None = None,
    workspace_kind: str = "dir",
    waiver: str | None = None,
    timeout_s: int | None = None,
    image: str | None = None,
) -> str:
    tid = kb.create_task(
        conn,
        title="oracle card",
        assignee="worker",
        workspace_kind=workspace_kind,
        workspace_path=workspace_path,
    )
    _set_oracle(
        conn,
        tid,
        kind=kind,
        cmd=cmd,
        timeout_s=timeout_s,
        image=image,
        waiver=waiver,
        workspace_path=workspace_path,
    )
    return tid


class _FakeDocker:
    def __init__(self, returncode: int = 0, stdout: str = "ok\n", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.calls: list[tuple[list[str], int]] = []
        self.exc: BaseException | None = None

    def __call__(self, argv: list[str], *, timeout_s: int):
        self.calls.append((list(argv), int(timeout_s)))
        if self.exc is not None:
            raise self.exc
        return SimpleNamespace(
            returncode=self.returncode,
            stdout=self.stdout,
            stderr=self.stderr,
        )


def _load_runner():
    from hermes_cli.kanban_oracle import run_oracle

    return run_oracle


# ---------------------------------------------------------------------------
# kind: none — waiver, no container
# ---------------------------------------------------------------------------


def test_kind_none_records_waiver_without_docker(kanban_home):
    run_oracle = _load_runner()
    docker = _FakeDocker()
    conn = kb.connect()
    try:
        tid = _seed_task(
            conn,
            kind="none",
            waiver="judgment-class ADR; no executable oracle",
        )
        receipt = run_oracle(conn, tid, docker_run=docker, invoked_by="test")
    finally:
        conn.close()

    assert docker.calls == []
    assert receipt["kind"] == "none"
    assert receipt["task_id"] == tid
    assert receipt["invoked_by"] == "test"
    assert receipt["rc"] is None
    assert "judgment-class" in (receipt["cmd"] or "")
    stored = kb.latest_oracle_receipt(kb.connect(), tid)
    assert stored is not None
    assert stored["id"] == receipt["id"]
    assert stored["rc"] is None


def test_missing_task_records_rc_2_without_raising(kanban_home):
    run_oracle = _load_runner()
    docker = _FakeDocker()
    conn = kb.connect()
    try:
        receipt = run_oracle(conn, "t_missing", docker_run=docker)
    finally:
        conn.close()
    assert docker.calls == []
    assert receipt["rc"] == 2
    assert receipt["task_id"] == "t_missing"


# ---------------------------------------------------------------------------
# Fail-closed workspace / git
# ---------------------------------------------------------------------------


def test_missing_workspace_records_rc_2(kanban_home, tmp_path):
    run_oracle = _load_runner()
    docker = _FakeDocker()
    missing = tmp_path / "does-not-exist"
    conn = kb.connect()
    try:
        tid = _seed_task(
            conn,
            kind="jest",
            cmd="foo.test.ts",
            workspace_path=str(missing),
        )
        receipt = run_oracle(conn, tid, docker_run=docker)
    finally:
        conn.close()
    assert docker.calls == []
    assert receipt["rc"] == 2
    assert receipt["kind"] == "jest"


def test_non_git_workspace_records_rc_2(kanban_home, tmp_path):
    run_oracle = _load_runner()
    docker = _FakeDocker()
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    conn = kb.connect()
    try:
        tid = _seed_task(
            conn,
            kind="shell",
            cmd="sh -c 'exit 0'",
            workspace_path=str(plain),
        )
        receipt = run_oracle(conn, tid, docker_run=docker)
    finally:
        conn.close()
    assert docker.calls == []
    assert receipt["rc"] == 2


def test_undeclared_kind_is_not_a_silent_pass(kanban_home, tmp_path):
    run_oracle = _load_runner()
    docker = _FakeDocker()
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    conn = kb.connect()
    try:
        tid = _seed_task(conn, kind=None, workspace_path=str(repo))
        receipt = run_oracle(conn, tid, docker_run=docker)
    finally:
        conn.close()
    assert docker.calls == []
    assert receipt["rc"] == 2


# ---------------------------------------------------------------------------
# Working-tree binding
# ---------------------------------------------------------------------------


def test_source_mutation_between_snapshots_records_rc_2(kanban_home, tmp_path):
    run_oracle = _load_runner()
    docker = _FakeDocker(returncode=0)
    repo = tmp_path / "repo"
    head = _init_git_repo(repo)
    snaps = [
        (head, b" M tracked.py\0"),
        (head, b" M tracked.py\0?? evil.py\0"),
    ]

    def snapshot(_workspace: Path):
        return snaps.pop(0)

    conn = kb.connect()
    try:
        tid = _seed_task(
            conn,
            kind="shell",
            cmd="sh -c 'exit 0'",
            workspace_path=str(repo),
        )
        receipt = run_oracle(
            conn,
            tid,
            docker_run=docker,
            snapshot_tree=snapshot,
        )
    finally:
        conn.close()

    assert receipt["rc"] == 2
    assert receipt["head_sha"] == head
    assert receipt["tree_hash"] == hashlib.sha256(b" M tracked.py\0").hexdigest()
    # Docker still ran — mutation is detected after the container.
    assert len(docker.calls) == 1


def test_clean_run_records_head_and_tree_hash(kanban_home, tmp_path):
    run_oracle = _load_runner()
    docker = _FakeDocker(returncode=0, stdout="PASS 5\n")
    repo = tmp_path / "repo"
    head = _init_git_repo(repo)
    porcelain = b""
    expected_hash = hashlib.sha256(porcelain).hexdigest()

    def snapshot(_workspace: Path):
        return (head, porcelain)

    conn = kb.connect()
    try:
        tid = _seed_task(
            conn,
            kind="jest",
            cmd="apps/foo.test.ts",
            workspace_path=str(repo),
            image="node:22-alpine",
            timeout_s=120,
        )
        receipt = run_oracle(
            conn,
            tid,
            docker_run=docker,
            snapshot_tree=snapshot,
            invoked_by="unit",
        )
    finally:
        conn.close()

    assert receipt["rc"] == 0
    assert receipt["head_sha"] == head
    assert receipt["tree_hash"] == expected_hash
    assert receipt["image"] == "node:22-alpine"
    assert receipt["kind"] == "jest"
    assert receipt["cmd"] == "apps/foo.test.ts"
    assert receipt["invoked_by"] == "unit"
    assert receipt["log_path"]
    assert Path(receipt["log_path"]).is_file()
    log_text = Path(receipt["log_path"]).read_text(encoding="utf-8")
    assert "PASS 5" in log_text


# ---------------------------------------------------------------------------
# Exit-code taxonomy + fail-open
# ---------------------------------------------------------------------------


def test_docker_137_maps_to_rc_3(kanban_home, tmp_path):
    run_oracle = _load_runner()
    docker = _FakeDocker(returncode=137)
    repo = tmp_path / "repo"
    head = _init_git_repo(repo)

    def snapshot(_workspace: Path):
        return (head, b"")

    conn = kb.connect()
    try:
        tid = _seed_task(
            conn, kind="tsc", cmd="-p tsconfig.base.json", workspace_path=str(repo)
        )
        receipt = run_oracle(conn, tid, docker_run=docker, snapshot_tree=snapshot)
    finally:
        conn.close()
    assert receipt["rc"] == 3


def test_timeout_maps_to_rc_124(kanban_home, tmp_path):
    run_oracle = _load_runner()
    docker = _FakeDocker()
    docker.exc = subprocess.TimeoutExpired(cmd=["docker"], timeout=9)
    repo = tmp_path / "repo"
    head = _init_git_repo(repo)

    def snapshot(_workspace: Path):
        return (head, b"")

    conn = kb.connect()
    try:
        tid = _seed_task(
            conn,
            kind="shell",
            cmd="sleep 99",
            workspace_path=str(repo),
            timeout_s=9,
        )
        receipt = run_oracle(conn, tid, docker_run=docker, snapshot_tree=snapshot)
    finally:
        conn.close()
    assert receipt["rc"] == 124
    assert docker.calls[0][1] == 9


def test_failing_command_records_nonzero(kanban_home, tmp_path):
    """A runner that cannot fail is worse than no runner (D-5)."""
    run_oracle = _load_runner()
    docker = _FakeDocker(returncode=7)
    repo = tmp_path / "repo"
    head = _init_git_repo(repo)

    def snapshot(_workspace: Path):
        return (head, b"")

    conn = kb.connect()
    try:
        tid = _seed_task(
            conn,
            kind="shell",
            cmd="sh -c 'exit 7'",
            workspace_path=str(repo),
        )
        receipt = run_oracle(conn, tid, docker_run=docker, snapshot_tree=snapshot)
    finally:
        conn.close()
    assert receipt["rc"] == 7
    assert receipt["rc"] != 0


def test_advisory_suspicious_cmd_flags_obvious_self_suppression():
    """Obvious spellings are flagged; obfuscation is out of scope on purpose."""
    from hermes_cli.kanban_oracle import advisory_suspicious_cmd

    assert advisory_suspicious_cmd("set +o pipefail; false | true")
    assert advisory_suspicious_cmd("set   +o   pipefail ; false | true")
    assert advisory_suspicious_cmd("sh -c 'set +o pipefail; false | true'")
    assert advisory_suspicious_cmd("eval 'set +o pipefail'; false | true")
    assert advisory_suspicious_cmd('sh -c \'trap "exit 0" EXIT; exit 4\'')
    assert not advisory_suspicious_cmd("false | true")
    assert not advisory_suspicious_cmd("true")
    assert not advisory_suspicious_cmd("pnpm exec jest apps/foo.test.ts")
    # Security theatre is rejected: obfuscation is not claimed to match.
    assert not advisory_suspicious_cmd("eval $(echo c2V0ICtvIHBpcGVmYWls | base64 -d)")


def test_advisory_suspicious_cmd_does_not_change_recorded_rc(kanban_home, tmp_path):
    """suspicious_cmd is log metadata. Fake docker rc=0 stays rc=0 (D-6)."""
    run_oracle = _load_runner()
    docker = _FakeDocker(returncode=0)
    repo = tmp_path / "repo"
    head = _init_git_repo(repo)

    def snapshot(_workspace: Path):
        return (head, b"")

    conn = kb.connect()
    try:
        tid = _seed_task(
            conn,
            kind="shell",
            cmd="set +o pipefail; false | true",
            workspace_path=str(repo),
        )
        receipt = run_oracle(
            conn, tid, docker_run=docker, snapshot_tree=snapshot, invoked_by="unit"
        )
    finally:
        conn.close()

    assert receipt["rc"] == 0
    log_text = Path(receipt["log_path"]).read_text(encoding="utf-8")
    assert "suspicious_cmd=yes" in log_text
    assert "not a refuse path" in log_text


def test_advisory_suspicious_cmd_absent_for_innocent_pipeline(kanban_home, tmp_path):
    """C2b-innocent ``false | true`` must not look like self-suppression."""
    run_oracle = _load_runner()
    docker = _FakeDocker(returncode=1)
    repo = tmp_path / "repo"
    head = _init_git_repo(repo)

    def snapshot(_workspace: Path):
        return (head, b"")

    conn = kb.connect()
    try:
        tid = _seed_task(
            conn,
            kind="shell",
            cmd="false | true",
            workspace_path=str(repo),
        )
        receipt = run_oracle(conn, tid, docker_run=docker, snapshot_tree=snapshot)
    finally:
        conn.close()

    assert receipt["rc"] == 1
    log_text = Path(receipt["log_path"]).read_text(encoding="utf-8")
    assert "suspicious_cmd=yes" not in log_text


def test_inner_script_does_not_pipe_the_gate_command():
    from hermes_cli.kanban_oracle import build_inner_script

    for kind, cmd in (
        ("jest", "apps/foo.test.ts"),
        ("tsc", "-p tsconfig.base.json"),
        ("shell", "sh -c 'exit 7'"),
    ):
        script = build_inner_script(kind=kind, cmd=cmd, results_dir="/results")
        # The fail-open bug was `gate | tail; echo rc=$?` capturing tail.
        assert "| tail" not in script
        assert "rc=$?" in script
        # Redirect, then capture, then tail the file — in that order.
        gate_redirect = script.index("> /results/out.log")
        rc_capture = script.index("rc=$?")
        tail_display = script.index("tail ")
        assert gate_redirect < rc_capture < tail_display


def _run_inner_script(
    inner: Path,
    *,
    workdir: Path,
    cmd: str,
    shell: str = "bash",
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Execute a generated wrapper the way a pipefail-capable shell would.

    Production runs ``sh /inner.sh`` inside ``node:22-alpine`` (busybox ash).
    Host ``/bin/sh`` is often dash, which rejects ``set -o pipefail`` and
    must take the rc=2 infra path — so local behavioral assertions use bash.
    """
    env = {
        **os.environ,
        "ORACLE_WORKDIR": str(workdir),
        "ORACLE_CMD": cmd,
    }
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [shell, str(inner)],
        cwd=str(workdir),
        env=env,
        capture_output=True,
        text=True,
    )


def _bash_as_sh_env(tmp_path: Path) -> dict[str, str]:
    """Put bash on PATH as ``sh`` so nested ``sh -c`` matches busybox ash.

    Host ``/bin/sh`` is typically dash, which treats ``set -o pipefail``
    as a fatal illegal option. Production ``node:22-alpine`` ash supports
    the option, so a nested ``sh -c 'set +o pipefail; …'`` can disable it
    and record rc=0. Characterising that limit locally requires a
    pipefail-capable ``sh``.
    """
    import shutil

    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash not available")
    bindir = tmp_path / "bash-as-sh"
    bindir.mkdir()
    (bindir / "sh").symlink_to(bash)
    return {"PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"}


def test_inner_script_failing_command_is_nonzero_locally(tmp_path):
    """Execute the generated wrapper with a known-failing command. No docker."""
    from hermes_cli.kanban_oracle import build_inner_script

    results = tmp_path / "results"
    results.mkdir()
    script = build_inner_script(
        kind="shell",
        cmd="sh -c 'echo TS1005: error; exit 1'",
        results_dir=str(results),
    )
    inner = tmp_path / "inner.sh"
    inner.write_text(script, encoding="utf-8")
    # Host /bin/sh is often dash (no pipefail → rc=2). Production is
    # busybox ash; local assertions use a pipefail-capable shell.
    proc = _run_inner_script(
        inner,
        workdir=tmp_path,
        cmd="sh -c 'echo TS1005: error; exit 1'",
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "TS1005" in (results / "out.log").read_text(encoding="utf-8")


def test_inner_script_exit_7_is_not_swallowed(tmp_path):
    from hermes_cli.kanban_oracle import build_inner_script

    results = tmp_path / "results"
    results.mkdir()
    script = build_inner_script(
        kind="shell",
        cmd="sh -c 'exit 7'",
        results_dir=str(results),
    )
    inner = tmp_path / "inner.sh"
    inner.write_text(script, encoding="utf-8")
    proc = _run_inner_script(inner, workdir=tmp_path, cmd="sh -c 'exit 7'")
    assert proc.returncode == 7


def test_inner_script_piped_failing_command_is_nonzero(tmp_path):
    """``sh -c 'exit 9' | tail -1`` must not record tail's rc=0 (C2b)."""
    from hermes_cli.kanban_oracle import build_inner_script

    results = tmp_path / "results"
    results.mkdir()
    cmd = "sh -c 'exit 9' | tail -1"
    script = build_inner_script(kind="shell", cmd=cmd, results_dir=str(results))
    inner = tmp_path / "inner.sh"
    inner.write_text(script, encoding="utf-8")
    proc = _run_inner_script(inner, workdir=tmp_path, cmd=cmd)
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert proc.returncode == 9, proc.stdout + proc.stderr


def test_inner_script_false_pipe_true_is_nonzero(tmp_path):
    """A pipeline whose last stage succeeds is still a failure (C2b)."""
    from hermes_cli.kanban_oracle import build_inner_script

    results = tmp_path / "results"
    results.mkdir()
    cmd = "false | true"
    script = build_inner_script(kind="shell", cmd=cmd, results_dir=str(results))
    inner = tmp_path / "inner.sh"
    inner.write_text(script, encoding="utf-8")
    proc = _run_inner_script(inner, workdir=tmp_path, cmd=cmd)
    assert proc.returncode != 0, proc.stdout + proc.stderr


def test_inner_script_true_and_true_pipe_true_still_pass(tmp_path):
    """Do not fix C2b by making genuine success fail."""
    from hermes_cli.kanban_oracle import build_inner_script

    results = tmp_path / "results"
    results.mkdir()
    for cmd in ("true", "true | true"):
        script = build_inner_script(kind="shell", cmd=cmd, results_dir=str(results))
        inner = tmp_path / "inner.sh"
        inner.write_text(script, encoding="utf-8")
        proc = _run_inner_script(inner, workdir=tmp_path, cmd=cmd)
        assert proc.returncode == 0, f"{cmd!r}: {proc.stdout}{proc.stderr}"


# ---------------------------------------------------------------------------
# Documented honesty-grade limits (DESIGN.md §3.0 / §4) — NOT bugs.
# A card that disables pipefail or rewrites exit via trap records the
# rewritten rc. Do not "fix" these with a string blocklist; that is
# security theatre (concat / base64 / nested printf walk through) and
# CAO is not a security boundary (D-6).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cmd",
    [
        "set +o pipefail; false | true",
        "set +o pipefail; sh -c 'exit 9' | tail -1",
        "set +o pipefail;false|true",
        "set   +o   pipefail ; false | true",
        "sh -c 'set +o pipefail; false | true'",
        "eval 'set +o pipefail'; false | true",
    ],
)
def test_documented_limit_card_can_disable_pipefail_rc0(tmp_path, cmd):
    """Characterisation: card-supplied pipefail disable records rc=0.

    This is the trap class, not the C2b class. C2b was an *innocent*
    pipeline (``false | true``) getting a wrong rc; that still must
    stay non-zero (see test_inner_script_false_pipe_true_is_nonzero).
    A card that turns the option off in its own context leaves nothing
    to capture. Honesty-grade does not defend against a card attacking
    itself.
    """
    from hermes_cli.kanban_oracle import build_inner_script

    results = tmp_path / "results"
    results.mkdir()
    script = build_inner_script(kind="shell", cmd=cmd, results_dir=str(results))
    inner = tmp_path / "inner.sh"
    inner.write_text(script, encoding="utf-8")
    proc = _run_inner_script(
        inner,
        workdir=tmp_path,
        cmd=cmd,
        extra_env=_bash_as_sh_env(tmp_path),
    )
    assert proc.returncode == 0, f"{cmd!r}: {proc.stdout}{proc.stderr}"
    # Wrapper must still eval card text as-is — no sanitise / refuse.
    assert "eval \"$ORACLE_CMD\"" in script


def test_documented_limit_card_can_trap_rewrite_exit_rc0(tmp_path):
    """Characterisation: trap-rewritten exits record as success (DESIGN.md §3.0)."""
    from hermes_cli.kanban_oracle import build_inner_script

    results = tmp_path / "results"
    results.mkdir()
    cmd = "sh -c 'trap \"exit 0\" EXIT; exit 4'"
    script = build_inner_script(kind="shell", cmd=cmd, results_dir=str(results))
    inner = tmp_path / "inner.sh"
    inner.write_text(script, encoding="utf-8")
    proc = _run_inner_script(inner, workdir=tmp_path, cmd=cmd)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_interpolating_kinds_require_pipefail_before_card_text():
    """jest/tsc/shell all interpolate card text — fix the class, not one branch."""
    from hermes_cli.kanban_oracle import build_inner_script

    for kind, cmd in (
        ("jest", "apps/foo.test.ts"),
        ("tsc", "-p tsconfig.base.json | true"),
        ("shell", "false | true"),
    ):
        script = build_inner_script(kind=kind, cmd=cmd, results_dir="/results")
        assert "set -o pipefail" in script
        assert script.index("set -o pipefail") < script.index("rc=$?")
        if kind == "tsc":
            # Unquoted $ORACLE_CMD can introduce a pipe; pipefail must precede it.
            gate = script.index("node \"$TSC\"")
            assert script.rfind("set -o pipefail", 0, gate) != -1


def test_inner_script_shell_without_pipefail_is_infra_not_pass(tmp_path):
    """A configured image whose sh lacks pipefail is rc=2, never a silent pass."""
    from hermes_cli.kanban_oracle import RC_INFRA, build_inner_script

    dash = Path("/usr/bin/dash")
    if not dash.is_file():
        pytest.skip("dash not installed")
    probe = subprocess.run(
        [str(dash), "-c", "set -o pipefail"],
        capture_output=True,
        text=True,
    )
    if probe.returncode == 0:
        pytest.skip("this dash supports pipefail")

    results = tmp_path / "results"
    results.mkdir()
    # Even a genuine success must not record rc=0 on a pipefail-less shell.
    cmd = "true"
    script = build_inner_script(kind="shell", cmd=cmd, results_dir=str(results))
    inner = tmp_path / "inner.sh"
    inner.write_text(script, encoding="utf-8")
    proc = _run_inner_script(inner, workdir=tmp_path, cmd=cmd, shell=str(dash))
    assert proc.returncode == RC_INFRA, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# Mounts + hardening flags (mocked docker argv)
# ---------------------------------------------------------------------------


def test_mounts_are_path_identical_and_come_from_card_workspace(
    kanban_home, tmp_path
):
    run_oracle = _load_runner()
    docker = _FakeDocker(returncode=0)
    workspace = tmp_path / "scratch-clone"
    head = _init_git_repo(workspace)
    main_checkout = tmp_path / "main-checkout"
    worktrees = tmp_path / "worktrees"
    main_checkout.mkdir()
    worktrees.mkdir()

    def snapshot(_workspace: Path):
        return (head, b"")

    conn = kb.connect()
    try:
        tid = _seed_task(
            conn,
            kind="jest",
            cmd="apps/foo.test.ts",
            workspace_path=str(workspace),
        )
        run_oracle(
            conn,
            tid,
            docker_run=docker,
            snapshot_tree=snapshot,
            config={
                "oracle_image": "node:22-alpine",
                "oracle_main_checkout": str(main_checkout),
                "oracle_worktrees_root": str(worktrees),
                "oracle_timeout_s": 90,
                "oracle_memory": "10g",
                "oracle_cpus": 6,
                "oracle_pids_limit": 2048,
            },
        )
    finally:
        conn.close()

    assert len(docker.calls) == 1
    argv, timeout_s = docker.calls[0]
    assert timeout_s == 90
    assert argv[0:3] == ["docker", "run", "--rm"]
    assert "--network=none" in argv
    assert "--cap-drop=ALL" in argv
    assert "--security-opt=no-new-privileges" in argv
    assert "--read-only" in argv
    assert "--tmpfs=/tmp:exec" in argv or "--tmpfs" in argv
    joined = " ".join(argv)
    assert "/tmp:exec" in joined
    assert "/scratch" in joined
    assert f"--user={os.getuid()}:{os.getgid()}" in argv or (
        "--user" in argv
        and f"{os.getuid()}:{os.getgid()}" in argv
    )
    assert f"{workspace}:{workspace}:ro" in joined
    assert f"{main_checkout}:{main_checkout}:ro" in joined
    assert f"{worktrees}:{worktrees}:ro" in joined
    # Workdir is the card tree, never a hardcoded main checkout.
    assert "-w" in argv
    w_idx = argv.index("-w")
    assert argv[w_idx + 1] == str(workspace)
    assert "node:22-alpine" in argv
    # Jest must not be invoked via the pnpm shell shim. Inspect the
    # generated wrapper (the host temp copy is deleted after the run).
    from hermes_cli.kanban_oracle import build_inner_script

    inner = build_inner_script(
        kind="jest", cmd="apps/foo.test.ts", results_dir="/results"
    )
    assert "node_modules/.bin/jest" not in inner
    assert "jest/bin/jest.js" in inner
    assert any("inner.sh" in tok for tok in argv)


def test_results_mount_is_writable_not_ro(kanban_home, tmp_path):
    run_oracle = _load_runner()
    docker = _FakeDocker(returncode=0)
    repo = tmp_path / "repo"
    head = _init_git_repo(repo)

    def snapshot(_workspace: Path):
        return (head, b"")

    conn = kb.connect()
    try:
        tid = _seed_task(
            conn, kind="shell", cmd="sh -c 'exit 0'", workspace_path=str(repo)
        )
        run_oracle(conn, tid, docker_run=docker, snapshot_tree=snapshot)
    finally:
        conn.close()
    argv = docker.calls[0][0]
    joined = " ".join(argv)
    assert ":/results" in joined
    assert ":/results:ro" not in joined


# ---------------------------------------------------------------------------
# Live container tests — explicit only
# ---------------------------------------------------------------------------


def _live_enabled() -> bool:
    return os.environ.get("CAO_ORACLE_LIVE") == "1"


def _live_prereqs() -> str | None:
    if not LIVE_REPO.is_dir():
        return f"missing {LIVE_REPO}"
    if not (LIVE_REPO / LIVE_JEST_TARGET).is_file():
        return f"missing {LIVE_JEST_TARGET}"
    if shutil_which("docker") is None:
        return "docker not on PATH"
    return None


def shutil_which(name: str) -> str | None:
    import shutil

    return shutil.which(name)


@pytest.mark.integration
def test_live_jest_appid_guard_records_pass(kanban_home):
    if not _live_enabled():
        pytest.skip("explicit live container test; set CAO_ORACLE_LIVE=1")
    reason = _live_prereqs()
    if reason:
        pytest.skip(reason)
    run_oracle = _load_runner()
    conn = kb.connect()
    try:
        tid = _seed_task(
            conn,
            kind="jest",
            cmd=LIVE_JEST_TARGET,
            workspace_path=str(LIVE_REPO),
            timeout_s=180,
            image="node:22-alpine",
        )
        receipt = run_oracle(
            conn,
            tid,
            invoked_by="live-positive",
            config={
                "oracle_image": "node:22-alpine",
                "oracle_main_checkout": str(LIVE_REPO),
                "oracle_worktrees_root": str(LIVE_WORKTREES),
                "oracle_timeout_s": 180,
            },
        )
    finally:
        conn.close()
    assert receipt["rc"] == 0, Path(receipt["log_path"]).read_text(encoding="utf-8")[-4000:]
    log_text = Path(receipt["log_path"]).read_text(encoding="utf-8")
    # 5 real assertions in appIdGuard.test.ts
    assert "5 passed" in log_text or "Tests:       5 passed" in log_text or (
        "PASS" in log_text and "5" in log_text
    )


@pytest.mark.integration
def test_live_nonexistent_test_path_records_rc_1(kanban_home):
    if not _live_enabled():
        pytest.skip("explicit live container test; set CAO_ORACLE_LIVE=1")
    reason = _live_prereqs()
    if reason:
        pytest.skip(reason)
    run_oracle = _load_runner()
    conn = kb.connect()
    try:
        tid = _seed_task(
            conn,
            kind="jest",
            cmd="apps/agent-gateway/tests/unit/telegram/DOES_NOT_EXIST.test.ts",
            workspace_path=str(LIVE_REPO),
            timeout_s=180,
            image="node:22-alpine",
        )
        receipt = run_oracle(
            conn,
            tid,
            invoked_by="live-negative",
            config={
                "oracle_image": "node:22-alpine",
                "oracle_main_checkout": str(LIVE_REPO),
                "oracle_worktrees_root": str(LIVE_WORKTREES),
                "oracle_timeout_s": 180,
            },
        )
    finally:
        conn.close()
    assert receipt["rc"] == 1, Path(receipt["log_path"]).read_text(encoding="utf-8")[-4000:]
