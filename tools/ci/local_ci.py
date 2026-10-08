#!/usr/bin/env python3
"""GitHub Actions 없이 .github/workflows/ci.yml 의 job 을 로컬에서 같은 명령으로 돌린다.

GitHub Actions 를 쓸 수 없을 때(결제·러너 장애 등) 검증 담당이 PR 의 CI 를 대신 돌리기 위한 도구다.
ci.yml 을 직접 읽으므로 CI 정의가 바뀌면 자동으로 따라간다.

동작:
  - job 마다 `git archive <ref>` 로 깨끗한 소스 복사본을 만들고, 그 안에서 `run:` 단계를 순서대로 실행한다.
    GitHub 과 같은 셸(`bash --noprofile --norc -eo pipefail`)을 쓴다.
  - `uses:` 단계(checkout, setup-python)는 건너뛴다. Python 은 실행마다 만드는 venv 로 대신한다.
  - `apt-get` 이 들어간 단계는 건너뛴다. 의존성은 미리 설치돼 있어야 한다 (`--install-deps` 로 한 번에 설치).
  - `if:` 가 붙은 job(workflow_dispatch 전용 soak-ci, lab 등)은 CI 와 같게 건너뛴다.
  - matrix 는 모든 조합으로 펼친다 (예: werror (gcc), werror (clang)).
  - job 은 포트 충돌을 피하려고 하나씩 순서대로 돌린다.

사용:
  python3 tools/ci/local_ci.py                     # 현재 HEAD
  python3 tools/ci/local_ci.py --ref pr49          # 다른 ref (git fetch origin pull/49/head:pr49)
  python3 tools/ci/local_ci.py --jobs test,oracle  # 일부 job 만
  python3 tools/ci/local_ci.py --install-deps      # ci.yml 의 apt 패키지를 먼저 설치 (root 또는 sudo)

결과: <out>/summary.md (마크다운 표 + 실패 로그 끝부분), <out>/<job>.log. 실패가 있으면 종료 코드 1.
"""
import argparse
import itertools
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML 이 필요하다: python3 -m pip install pyyaml")

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = ".github/workflows/ci.yml"
JOB_TIMEOUT_S = 45 * 60
TAIL_LINES = 40
MATRIX_RE = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=True, **kw)


def expand_jobs(workflow):
    """(표시 이름, job 키, job 정의, matrix 값) 목록. if: 가 붙은 job 은 skip 표시."""
    out = []
    for key, job in workflow["jobs"].items():
        matrix = (job.get("strategy") or {}).get("matrix") or {}
        axes = {k: v for k, v in matrix.items() if isinstance(v, list)}
        if axes:
            names = list(axes)
            for combo in itertools.product(*(axes[n] for n in names)):
                values = dict(zip(names, combo))
                label = f"{key} ({', '.join(str(v) for v in combo)})"
                out.append((label, key, job, values))
        else:
            out.append((key, key, job, {}))
    return out


def substitute(text, matrix):
    def repl(m):
        name = m.group(1)
        if name not in matrix:
            raise KeyError(f"matrix.{name} 값이 없다")
        return str(matrix[name])

    return MATRIX_RE.sub(repl, text)


def apt_packages(workflow):
    pkgs = set()
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            run = step.get("run", "")
            for m in re.finditer(r"apt-get install -y ([^\n&;|]+)", run):
                pkgs.update(p for p in m.group(1).split() if not p.startswith("-"))
    return sorted(pkgs)


# ci.yml 의 apt 줄에는 없지만 로컬 실행에 필요한 패키지. GitHub 러너는 actions/setup-python 으로 venv·pip 를
# 얻지만, 로컬은 시스템 python3 로 venv 를 만들므로 Ubuntu 에서 python3-venv(ensurepip)가 필요하다 (#97).
LOCAL_EXTRA_APT = ["python3-venv"]


def install_deps(workflow):
    pkgs = sorted(set(apt_packages(workflow)) | set(LOCAL_EXTRA_APT))
    prefix = [] if os.geteuid() == 0 else ["sudo"]
    print(f"[local-ci] apt 패키지 설치: {' '.join(pkgs)}", flush=True)
    sh(prefix + ["apt-get", "update", "-q"])
    sh(prefix + ["apt-get", "install", "-y", "-q"] + pkgs)


def export_source(ref, dest):
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    archive = subprocess.run(
        ["git", "-C", str(REPO), "archive", ref], check=True, capture_output=True
    ).stdout
    subprocess.run(["tar", "-x", "-C", str(dest)], input=archive, check=True)


def ensure_venv(out):
    venv = out / ".venv"
    if not (venv / "bin" / "python").exists():
        sh([sys.executable, "-m", "venv", str(venv)])
        sh([str(venv / "bin" / "python"), "-m", "pip", "install", "-q", "--upgrade", "pip"])
    return venv


def run_job(label, job, matrix, ref, out, venv):
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("_")
    src = out / "jobs" / safe
    log_path = out / f"{safe}.log"
    export_source(ref, src)
    env = os.environ.copy()
    env["PATH"] = f"{venv / 'bin'}{os.pathsep}{env['PATH']}"
    env["CI"] = "true"
    env.update({k: str(v) for k, v in (job.get("env") or {}).items()})
    started = time.monotonic()
    notes = []
    with open(log_path, "w") as log:
        for i, step in enumerate(job.get("steps", []), 1):
            name = step.get("name") or step.get("uses") or f"step {i}"
            if "uses" in step:
                log.write(f"\n### [건너뜀] {name} (uses: {step['uses']})\n")
                continue
            run = substitute(step.get("run", ""), matrix)
            if "apt-get" in run:
                log.write(f"\n### [건너뜀] {name} (apt 의존성은 미리 설치)\n")
                notes.append("apt 단계 건너뜀")
                continue
            step_env = env.copy()
            step_env.update({k: substitute(str(v), matrix) for k, v in (step.get("env") or {}).items()})
            log.write(f"\n### {name}\n$ {run}\n")
            log.flush()
            remaining = JOB_TIMEOUT_S - (time.monotonic() - started)
            try:
                rc = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", run],
                    cwd=src, env=step_env, stdout=log, stderr=subprocess.STDOUT,
                    timeout=max(remaining, 1),
                ).returncode
            except subprocess.TimeoutExpired:
                log.write(f"\n[local-ci] 시간 초과 ({JOB_TIMEOUT_S}s)\n")
                return "FAIL", time.monotonic() - started, f"{name}: 시간 초과", log_path
            if rc != 0:
                log.write(f"\n[local-ci] 실패: 종료 코드 {rc}\n")
                return "FAIL", time.monotonic() - started, f"{name}: 종료 코드 {rc}", log_path
    return "PASS", time.monotonic() - started, "; ".join(sorted(set(notes))), log_path


def tail(path, n):
    lines = path.read_text(errors="replace").splitlines()
    return "\n".join(lines[-n:])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ref", default="HEAD", help="검사할 git ref (기본 HEAD)")
    ap.add_argument("--jobs", default="", help="쉼표로 구분한 job 키 (기본: 전부)")
    ap.add_argument("--out", default="", help="결과 디렉토리 (기본: build-localci/<sha>)")
    ap.add_argument("--install-deps", action="store_true", help="ci.yml 의 apt 패키지를 먼저 설치")
    args = ap.parse_args()

    sha = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", args.ref], check=True, capture_output=True, text=True
    ).stdout.strip()
    workflow_text = subprocess.run(
        ["git", "-C", str(REPO), "show", f"{sha}:{WORKFLOW}"], check=True, capture_output=True, text=True
    ).stdout
    workflow = yaml.safe_load(workflow_text)
    if args.install_deps:
        install_deps(workflow)

    out = Path(args.out) if args.out else REPO / "build-localci" / sha[:12]
    out.mkdir(parents=True, exist_ok=True)
    venv = ensure_venv(out)
    wanted = {j.strip() for j in args.jobs.split(",") if j.strip()}

    results = []
    for label, key, job, matrix in expand_jobs(workflow):
        if wanted and key not in wanted:
            continue
        if "if" in job:
            results.append((label, "SKIP", 0.0, f"조건부 job (`if: {job['if']}`) — CI 에서도 기본 실행 안 됨", None))
            print(f"[local-ci] {label}: SKIP", flush=True)
            continue
        print(f"[local-ci] {label}: 실행 중...", flush=True)
        status, secs, note, log_path = run_job(label, job, matrix, sha, out, venv)
        print(f"[local-ci] {label}: {status} ({secs:.0f}s) {note}", flush=True)
        results.append((label, status, secs, note, log_path))

    failed = [r for r in results if r[1] == "FAIL"]
    lines = [
        f"## 로컬 CI — {'FAIL' if failed else 'PASS'}",
        "",
        f"ref `{args.ref}` · commit `{sha[:7]}` · 정의 `{WORKFLOW}` (같은 커밋의 것)",
        "",
        "| job | 결과 | 시간 | 비고 |",
        "|---|---|---|---|",
    ]
    for label, status, secs, note, _ in results:
        mark = {"PASS": "✅", "FAIL": "❌", "SKIP": "—"}[status]
        lines.append(f"| {label} | {mark} {status} | {secs:.0f}s | {note} |")
    for label, _, _, note, log_path in failed:
        lines += ["", f"### {label} 실패 로그 (끝 {TAIL_LINES}줄)", "", "```", tail(log_path, TAIL_LINES), "```"]
    summary = "\n".join(lines) + "\n"
    (out / "summary.md").write_text(summary)
    print("\n" + summary)
    print(f"[local-ci] 결과: {out / 'summary.md'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
