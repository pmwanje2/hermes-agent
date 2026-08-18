"""Card Acceptance Oracle runner — record a receipt, do not enforce.

This is an honesty-gate audit trail, not a security boundary. Workers
run same-uid, hold a real shell, and can write ``task_oracle_runs``
directly. ``run_oracle`` records what the declared command returned
against the card's workspace; it does not refuse completion (that is
a later phase, and even then it is advisory until a privilege boundary
exists).

Never pipe the gate command. Redirect to a file, capture ``$?`` on the
very next line, then tail the file for display. A piped
``cmd | tail; echo rc=$?`` reports the tail's exit code — green when
red — which is the defect this runner exists to prevent.

Card-supplied pipelines have the same class of bug one layer down:
POSIX ``sh`` returns the last stage, so ``sh -c 'exit 9' | tail -1``
and ``false | true`` would record rc=0. The wrapper therefore
``set -o pipefail`` before any interpolation of card text. A
configured image whose ``sh`` lacks the option (dash) is rc=2 infra,
never a silent pass. Busybox ash in the pinned ``node:22-alpine``
image supports it.

Honesty-grade limits (DESIGN.md §3.0 / §4), not defects: a command
that deliberately rewrites its own exit — ``trap "exit 0" EXIT;
exit 4`` — or disables the wrapper's fail-closed option —
``set +o pipefail; false | true`` (including nested ``sh -c`` and
``eval``-wrapped spellings) — is indistinguishable from genuine
success at this layer and records rc=0. That is a truthful receipt
of a command that lied. The wrapper does not block, sanitise, or
rewrite card text; a string blocklist is security theatre and is
rejected. Pipefail protects *innocent* pipelines (C2b). It does
not defend against a card attacking itself. Obvious self-suppression
in the *declared* command may be noted as ``suspicious_cmd`` on the
receipt log — advisory metadata for a human reviewer, never
enforcement, never a refuse path.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from hermes_cli import kanban_db as kb  # in-tree

ORACLE_KINDS = frozenset({"jest", "tsc", "shell", "none"})

DEFAULT_IMAGE = "node:22-alpine"
DEFAULT_TIMEOUT_S = 900
DEFAULT_MEMORY = "10g"
DEFAULT_CPUS = 6
DEFAULT_PIDS_LIMIT = 2048

# D-3 taxonomy
RC_PASS = 0
RC_FAIL = 1
RC_INFRA = 2
RC_OOM = 3
RC_TIMEOUT = 124
DOCKER_OOM_RC = 137

DockerRun = Callable[..., Any]
SnapshotFn = Callable[[Path], tuple[str, bytes]]


def build_inner_script(*, kind: str, cmd: str, results_dir: str) -> str:
    """Return the in-container / local wrapper script.

    The gate command is redirected to ``{results_dir}/out.log``. ``rc=$?``
    is captured on the next line. ``tail`` is display-only and must never
    sit on the same pipe as the gate.

    ``set -o pipefail`` is required before any interpolation of card
    text. Without it, POSIX ``sh`` reports the last pipeline stage
    (``false | true`` → 0). A shell that rejects the option exits
    ``RC_INFRA`` (2). A card command that rewrites its own status
    via ``trap ... EXIT`` or ``set +o pipefail`` still records that
    rewritten rc — honesty grade, not a guarantee. Do not refuse or
    rewrite those spellings here.
    """
    out = f"{results_dir}/out.log"
    kind = (kind or "").strip().lower()
    # ``cmd`` is supplied at runtime via ORACLE_CMD (never interpolated into
    # the executable line). Record a sanitized copy so a mounted inner.sh
    # is inspectable after a failure.
    declared = (cmd or "").replace("\n", " ").replace("\r", " ")[:200]
    # Probe in a subshell: dash treats ``set -o pipefail`` as a fatal
    # illegal option that ``||`` cannot catch in the same shell.
    header = f"""\
#!/bin/sh
# CAO inner wrapper. Recorded/advisory. Do not pipe the gate command.
# Honesty-grade: trap / set +o pipefail self-suppression records as success.
# declared_cmd={declared}
set -u
: "${{ORACLE_CMD:?oracle cmd unset}}"
: "${{ORACLE_WORKDIR:?oracle workdir unset}}"
if ! (set -o pipefail) 2>/dev/null; then
  echo "ORACLE_RC={RC_INFRA} (infra: set -o pipefail unsupported)"
  exit {RC_INFRA}
fi
set -o pipefail || {{ echo "ORACLE_RC={RC_INFRA} (infra: set -o pipefail failed)"; exit {RC_INFRA}; }}
cd "$ORACLE_WORKDIR" || {{ echo "ORACLE_RC={RC_INFRA} (infra: workdir missing)"; exit {RC_INFRA}; }}
"""
    if kind == "jest":
        body = f"""\
# Discovery pipeline is ours (ls | head); disable pipefail so SIGPIPE
# from head cannot look like a missing jest. Re-enable before the gate.
set +o pipefail
JESTJS=$(ls -d "$ORACLE_WORKDIR"/node_modules/.pnpm/jest@*/node_modules/jest/bin/jest.js 2>/dev/null | head -1)
set -o pipefail || {{ echo "ORACLE_RC={RC_INFRA} (infra: set -o pipefail failed)"; exit {RC_INFRA}; }}
echo "resolved_jest=${{JESTJS:-NONE}}"
[ -z "$JESTJS" ] && {{ echo "ORACLE_RC={RC_INFRA} (infra: jest entrypoint unresolved)"; exit {RC_INFRA}; }}
node "$JESTJS" --ci --runInBand --no-coverage "$ORACLE_CMD" > {out} 2>&1
rc=$?
"""
    elif kind == "tsc":
        body = f"""\
set +o pipefail
TSC=$(ls -d "$ORACLE_WORKDIR"/node_modules/.pnpm/typescript@*/node_modules/typescript/bin/tsc 2>/dev/null | head -1)
# Extra flags come from the card (e.g. -p tsconfig.base.json). Unquoted on
# purpose so tokens split; pipefail is on so a card-supplied ``|`` cannot
# hide a failing tsc behind a succeeding last stage.
set -o pipefail || {{ echo "ORACLE_RC={RC_INFRA} (infra: set -o pipefail failed)"; exit {RC_INFRA}; }}
echo "resolved_tsc=${{TSC:-NONE}}"
[ -z "$TSC" ] && {{ echo "ORACLE_RC={RC_INFRA} (infra: tsc entrypoint unresolved)"; exit {RC_INFRA}; }}
node "$TSC" --noEmit $ORACLE_CMD > {out} 2>&1
rc=$?
"""
    elif kind == "shell":
        body = f"""\
# Subshell inherits this wrapper's already-probed pipefail. A nested
# ``sh -c "$ORACLE_CMD"`` would spawn the image's /bin/sh without
# pipefail and fail-open on ``false | true``. ``set +u`` is local to
# the subshell so card text is not under the wrapper's nounset.
# ``exit`` in the card stays inside the subshell so the footer records rc.
( set +u; eval "$ORACLE_CMD" ) > {out} 2>&1
rc=$?
"""
    else:
        body = f"""\
echo "ORACLE_RC={RC_INFRA} (infra: unknown kind)" > {out}
rc={RC_INFRA}
"""
    footer = f"""\
tail -20 {out}
echo "ORACLE_RC=$rc"
exit $rc
"""
    return header + body + footer


def snapshot_working_tree(workspace: Path) -> tuple[str, bytes]:
    """Capture ``HEAD`` and porcelain-v1 -z status (content/mode/kind).

    ``tree_hash`` is sha256 of the porcelain bytes, not of mtimes.
    Raises ``OSError`` / ``subprocess.CalledProcessError`` when the
    workspace is not a git checkout — callers map that to rc=2.
    """
    head_proc = subprocess.run(
        ["git", "-C", str(workspace), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
    )
    status_proc = subprocess.run(
        [
            "git",
            "-C",
            str(workspace),
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ],
        check=True,
        capture_output=True,
    )
    head = head_proc.stdout.decode("ascii", errors="replace").strip()
    return head, status_proc.stdout


def tree_hash_of(porcelain: bytes) -> str:
    return hashlib.sha256(porcelain).hexdigest()


def map_container_rc(docker_rc: int) -> int:
    """Map a container/subprocess exit code onto the D-3 taxonomy."""
    if docker_rc == DOCKER_OOM_RC:
        return RC_OOM
    return docker_rc


# Obvious self-suppression in the *declared* command. Advisory only —
# a human-reviewer hint on the receipt log. Never changes rc, never
# refuses, never rewrites card text. Obfuscated spellings (concat,
# base64, printf) will not match; that is accepted. CAO is not a
# security boundary (D-6).
_SUSPICIOUS_CMD_RE = re.compile(
    r"(?:set\s+\+o\s+pipefail)|(?:set\s+\+pipefail)|(?:trap\s+['\"]?exit\s+0)",
    re.IGNORECASE,
)


def advisory_suspicious_cmd(cmd: str) -> bool:
    """True when the declared command *obviously* self-suppresses.

    Advisory metadata for a human reviewer. Must never change rc or
    refuse completion. Obfuscated spellings are out of scope on purpose.
    """
    if not cmd:
        return False
    return bool(_SUSPICIOUS_CMD_RE.search(cmd))


def default_docker_run(argv: list[str], *, timeout_s: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )


def _load_oracle_config(overrides: Optional[Mapping[str, Any]] = None) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "oracle_image": DEFAULT_IMAGE,
        "oracle_timeout_s": DEFAULT_TIMEOUT_S,
        "oracle_memory": DEFAULT_MEMORY,
        "oracle_cpus": DEFAULT_CPUS,
        "oracle_pids_limit": DEFAULT_PIDS_LIMIT,
        "oracle_main_checkout": "",
        "oracle_worktrees_root": "",
    }
    try:
        from hermes_cli.config import load_config

        kanban = (load_config() or {}).get("kanban") or {}
        if isinstance(kanban, dict):
            for key in (
                "oracle_image",
                "oracle_timeout_s",
                "oracle_memory",
                "oracle_cpus",
                "oracle_pids_limit",
                "oracle_main_checkout",
                "oracle_worktrees_root",
            ):
                if key in kanban and kanban[key] not in (None, ""):
                    cfg[key] = kanban[key]
    except Exception:
        pass
    if overrides:
        for key, value in overrides.items():
            if value is not None:
                cfg[key] = value
    return cfg


def _task_row(conn: sqlite3.Connection, task_id: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM tasks WHERE id = ?", (task_id,)
    ).fetchone()


def _row_get(row: sqlite3.Row, key: str, default: Any = None) -> Any:
    keys = row.keys()
    if key not in keys:
        return default
    value = row[key]
    return default if value is None else value


def _board_of(conn: sqlite3.Connection) -> Optional[str]:
    """Board slug for this connection, derived from the DB path.

    ``<root>/kanban/boards/<slug>/kanban.db`` -> ``<slug>``; the legacy
    ``<root>/kanban/kanban.db`` -> ``default``. Returns None if it cannot be
    determined, in which case the caller falls back to the current board.
    """
    try:
        for _, name, path in conn.execute("PRAGMA database_list"):
            if name == "main" and path:
                p = Path(path).resolve()
                parts = p.parts
                if "boards" in parts:
                    i = parts.index("boards")
                    if i + 1 < len(parts):
                        return parts[i + 1]
                return "default"
    except Exception:
        pass
    return None


def _durable_log_path(task_id: str, started_at: int, board: Optional[str] = None) -> Path:
    # Logs must follow the task's OWN board. Calling worker_logs_dir() with no
    # board resolves to whatever board is globally "current", which misfiles a
    # merge-conflicts receipt under boards/maximus/. Found 2026-08-18 while
    # re-verifying the first live receipt.
    try:
        log_dir = kb.worker_logs_dir(board=board) / "oracle"
    except TypeError:  # older kanban_db without the board kwarg
        log_dir = kb.worker_logs_dir() / "oracle"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / f"{task_id}-{started_at}.log"


def _insert_receipt(
    conn: sqlite3.Connection,
    *,
    task_id: str,
    run_id: Optional[int],
    kind: str,
    cmd: str,
    image: Optional[str],
    head_sha: Optional[str],
    tree_hash: Optional[str],
    started_at: int,
    ended_at: int,
    rc: Optional[int],
    log_path: Optional[str],
    invoked_by: Optional[str],
) -> dict:
    with kb.write_txn(conn, allow_nested=True):
        cur = conn.execute(
            """
            INSERT INTO task_oracle_runs (
                task_id, run_id, kind, cmd, image, head_sha, tree_hash,
                started_at, ended_at, rc, log_path, invoked_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task_id,
                run_id,
                kind,
                cmd,
                image,
                head_sha,
                tree_hash,
                started_at,
                ended_at,
                rc,
                log_path,
                invoked_by,
            ),
        )
        rid = cur.lastrowid
        row = conn.execute(
            "SELECT * FROM task_oracle_runs WHERE id = ?", (rid,)
        ).fetchone()
    return {key: row[key] for key in row.keys()}


def _write_log(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _format_log(
    *,
    header_lines: list[str],
    stdout: str = "",
    stderr: str = "",
    out_log: str = "",
) -> str:
    parts = [
        "# CAO oracle receipt (recorded / advisory; not a security boundary)",
        *header_lines,
        "",
        "----- docker stdout -----",
        stdout.rstrip() if stdout else "(empty)",
        "",
        "----- docker stderr -----",
        stderr.rstrip() if stderr else "(empty)",
        "",
        "----- results/out.log -----",
        out_log.rstrip() if out_log else "(empty)",
        "",
    ]
    return "\n".join(parts) + "\n"


def _existing_dir(value: Any) -> Optional[Path]:
    if not value:
        return None
    path = Path(str(value)).expanduser()
    return path if path.is_dir() else None


def _bind_ro(path: Path) -> str:
    resolved = str(path)
    return f"{resolved}:{resolved}:ro"


def _build_docker_argv(
    *,
    workspace: Path,
    image: str,
    inner_host: Path,
    results_host: Path,
    main_checkout: Optional[Path],
    worktrees_root: Optional[Path],
    memory: str,
    cpus: Any,
    pids_limit: Any,
    cmd: str,
) -> list[str]:
    uid = os.getuid()
    gid = os.getgid()
    argv: list[str] = [
        "docker",
        "run",
        "--rm",
        f"--user={uid}:{gid}",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--tmpfs=/tmp:exec",
        "--tmpfs=/scratch",
        f"--memory={memory}",
        f"--cpus={cpus}",
        f"--pids-limit={pids_limit}",
        "-v",
        _bind_ro(workspace),
    ]
    seen = {str(workspace)}
    for extra in (main_checkout, worktrees_root):
        if extra is None:
            continue
        key = str(extra)
        if key in seen:
            continue
        if not extra.is_dir():
            continue
        argv.extend(["-v", _bind_ro(extra)])
        seen.add(key)
    argv.extend(
        [
            "-v",
            f"{results_host}:/results",
            "-v",
            f"{inner_host}:/inner.sh:ro",
            "-w",
            str(workspace),
            "-e",
            "NODE_OPTIONS=--max-old-space-size=8192",
            "-e",
            "CI=true",
            "-e",
            f"ORACLE_WORKDIR={workspace}",
            "-e",
            f"ORACLE_CMD={cmd}",
            image,
            "sh",
            "/inner.sh",
        ]
    )
    return argv


def run_oracle(
    conn: sqlite3.Connection,
    task_id: str,
    *,
    docker_run: Optional[DockerRun] = None,
    snapshot_tree: Optional[SnapshotFn] = None,
    config: Optional[Mapping[str, Any]] = None,
    invoked_by: Optional[str] = None,
) -> dict:
    """Run the card's declared oracle and record a receipt.

    Returns the inserted ``task_oracle_runs`` row as a dict. Never
    raises for a missing card / missing workspace / red oracle — those
    are recorded as rc=2 / rc=1. A runner exception is recorded as
    rc=2 when possible; unexpected bugs still propagate so they are
    visible to the caller (C3 must catch them).
    """
    started_at = int(time.time())
    cfg = _load_oracle_config(config)
    docker_fn = docker_run or default_docker_run
    snap_fn = snapshot_tree or snapshot_working_tree

    row = _task_row(conn, task_id)
    if row is None:
        log_path = _durable_log_path(task_id, started_at)
        _write_log(
            log_path,
            _format_log(
                header_lines=[
                    f"task_id={task_id}",
                    "error=task not found",
                    f"rc={RC_INFRA}",
                ]
            ),
        )
        return _insert_receipt(
            conn,
            task_id=task_id,
            run_id=None,
            kind="none",
            cmd="(task not found)",
            image=None,
            head_sha=None,
            tree_hash=None,
            started_at=started_at,
            ended_at=int(time.time()),
            rc=RC_INFRA,
            log_path=str(log_path),
            invoked_by=invoked_by,
        )

    kind_raw = _row_get(row, "oracle_kind")
    kind = str(kind_raw).strip().lower() if kind_raw else ""
    cmd = str(_row_get(row, "oracle_cmd", "") or "")
    waiver = str(_row_get(row, "oracle_waiver_reason", "") or "")
    image = str(_row_get(row, "oracle_image") or cfg.get("oracle_image") or DEFAULT_IMAGE)
    timeout_s = _row_get(row, "oracle_timeout_s")
    if timeout_s is None:
        timeout_s = cfg.get("oracle_timeout_s", DEFAULT_TIMEOUT_S)
    try:
        timeout_s = int(timeout_s)
    except (TypeError, ValueError):
        timeout_s = DEFAULT_TIMEOUT_S
    if timeout_s <= 0:
        timeout_s = DEFAULT_TIMEOUT_S
    run_id = _row_get(row, "current_run_id")
    workspace_raw = _row_get(row, "workspace_path")

    def finish(
        *,
        rc: Optional[int],
        kind_out: str,
        cmd_out: str,
        head_sha: Optional[str] = None,
        tree_hash: Optional[str] = None,
        image_out: Optional[str] = None,
        log_text: str,
    ) -> dict:
        ended_at = int(time.time())
        log_path = _durable_log_path(task_id, started_at, board=_board_of(conn))
        _write_log(log_path, log_text)
        return _insert_receipt(
            conn,
            task_id=task_id,
            run_id=int(run_id) if run_id is not None else None,
            kind=kind_out,
            cmd=cmd_out,
            image=image_out,
            head_sha=head_sha,
            tree_hash=tree_hash,
            started_at=started_at,
            ended_at=ended_at,
            rc=rc,
            log_path=str(log_path),
            invoked_by=invoked_by,
        )

    if kind == "none":
        cmd_out = waiver or cmd or "(waiver)"
        return finish(
            rc=None,
            kind_out="none",
            cmd_out=cmd_out,
            log_text=_format_log(
                header_lines=[
                    f"task_id={task_id}",
                    "kind=none",
                    f"waiver={cmd_out}",
                    "container=skipped",
                    "rc=",
                ]
            ),
        )

    if kind not in ORACLE_KINDS:
        return finish(
            rc=RC_INFRA,
            kind_out=kind or "none",
            cmd_out=cmd or "(undeclared oracle)",
            log_text=_format_log(
                header_lines=[
                    f"task_id={task_id}",
                    f"kind={kind or '(undeclared)'}",
                    f"rc={RC_INFRA}",
                    "error=undeclared or unknown oracle kind; not a silent pass",
                ]
            ),
        )

    if not cmd.strip():
        return finish(
            rc=RC_INFRA,
            kind_out=kind,
            cmd_out="(empty oracle_cmd)",
            image_out=image,
            log_text=_format_log(
                header_lines=[
                    f"task_id={task_id}",
                    f"kind={kind}",
                    f"rc={RC_INFRA}",
                    "error=oracle_cmd is empty",
                ]
            ),
        )

    if not workspace_raw:
        return finish(
            rc=RC_INFRA,
            kind_out=kind,
            cmd_out=cmd,
            image_out=image,
            log_text=_format_log(
                header_lines=[
                    f"task_id={task_id}",
                    f"kind={kind}",
                    f"rc={RC_INFRA}",
                    "error=workspace_path is missing",
                ]
            ),
        )

    workspace = Path(str(workspace_raw)).expanduser()
    if not workspace.is_dir():
        return finish(
            rc=RC_INFRA,
            kind_out=kind,
            cmd_out=cmd,
            image_out=image,
            log_text=_format_log(
                header_lines=[
                    f"task_id={task_id}",
                    f"kind={kind}",
                    f"workspace={workspace}",
                    f"rc={RC_INFRA}",
                    "error=workspace_path does not exist",
                ]
            ),
        )

    try:
        head_before, porcelain_before = snap_fn(workspace)
    except Exception as exc:
        return finish(
            rc=RC_INFRA,
            kind_out=kind,
            cmd_out=cmd,
            image_out=image,
            log_text=_format_log(
                header_lines=[
                    f"task_id={task_id}",
                    f"kind={kind}",
                    f"workspace={workspace}",
                    f"rc={RC_INFRA}",
                    f"error=working-tree snapshot failed (non-git or missing): {exc}",
                ]
            ),
        )

    hash_before = tree_hash_of(porcelain_before)
    main_checkout = _existing_dir(cfg.get("oracle_main_checkout"))
    worktrees_root = _existing_dir(cfg.get("oracle_worktrees_root"))

    results_host = Path(tempfile.mkdtemp(prefix=f"cao-oracle-{task_id}-"))
    inner_host = results_host / "inner.sh"
    inner_host.write_text(
        build_inner_script(kind=kind, cmd=cmd, results_dir="/results"),
        encoding="utf-8",
    )
    inner_host.chmod(0o755)

    argv = _build_docker_argv(
        workspace=workspace,
        image=image,
        inner_host=inner_host,
        results_host=results_host,
        main_checkout=main_checkout,
        worktrees_root=worktrees_root,
        memory=str(cfg.get("oracle_memory") or DEFAULT_MEMORY),
        cpus=cfg.get("oracle_cpus", DEFAULT_CPUS),
        pids_limit=cfg.get("oracle_pids_limit", DEFAULT_PIDS_LIMIT),
        cmd=cmd,
    )

    docker_stdout = ""
    docker_stderr = ""
    out_log = ""
    mapped_rc = RC_INFRA
    try:
        try:
            completed = docker_fn(argv, timeout_s=timeout_s)
            docker_rc = int(getattr(completed, "returncode", RC_INFRA))
            docker_stdout = getattr(completed, "stdout", "") or ""
            docker_stderr = getattr(completed, "stderr", "") or ""
            mapped_rc = map_container_rc(docker_rc)
        except subprocess.TimeoutExpired as exc:
            docker_stdout = getattr(exc, "stdout", "") or ""
            docker_stderr = getattr(exc, "stderr", "") or ""
            if isinstance(docker_stdout, bytes):
                docker_stdout = docker_stdout.decode("utf-8", errors="replace")
            if isinstance(docker_stderr, bytes):
                docker_stderr = docker_stderr.decode("utf-8", errors="replace")
            mapped_rc = RC_TIMEOUT
        except FileNotFoundError as exc:
            docker_stderr = str(exc)
            mapped_rc = RC_INFRA
        except Exception as exc:
            docker_stderr = f"{type(exc).__name__}: {exc}"
            mapped_rc = RC_INFRA

        out_file = results_host / "out.log"
        if out_file.is_file():
            out_log = out_file.read_text(encoding="utf-8", errors="replace")

        try:
            head_after, porcelain_after = snap_fn(workspace)
        except Exception as exc:
            mapped_rc = RC_INFRA
            docker_stderr = (docker_stderr + f"\nafter-snapshot failed: {exc}").strip()
            head_after, porcelain_after = head_before, porcelain_before

        if head_after != head_before or porcelain_after != porcelain_before:
            mapped_rc = RC_INFRA
            docker_stderr = (
                docker_stderr
                + "\nsource mutation detected between before/after working-tree snapshots"
            ).strip()

        header_lines = [
            f"task_id={task_id}",
            f"kind={kind}",
            f"cmd={cmd}",
            f"image={image}",
            f"workspace={workspace}",
            f"head_sha={head_before}",
            f"tree_hash={hash_before}",
            f"timeout_s={timeout_s}",
            f"rc={mapped_rc}",
            f"argv={' '.join(argv)}",
        ]
        # Advisory only. Never changes mapped_rc / never refuses.
        if advisory_suspicious_cmd(cmd):
            header_lines.append(
                "suspicious_cmd=yes "
                "(advisory; card text looks like self-suppression; "
                "honesty-grade — not a refuse path)"
            )
        log_text = _format_log(
            header_lines=header_lines,
            stdout=docker_stdout,
            stderr=docker_stderr,
            out_log=out_log,
        )
        return finish(
            rc=mapped_rc,
            kind_out=kind,
            cmd_out=cmd,
            head_sha=head_before,
            tree_hash=hash_before,
            image_out=image,
            log_text=log_text,
        )
    finally:
        try:
            for child in results_host.iterdir():
                try:
                    child.unlink()
                except OSError:
                    pass
            results_host.rmdir()
        except OSError:
            pass
