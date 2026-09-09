#!/usr/bin/env python3
"""Compile CTT board data from YAML scenarios + coverage matrices.

Walks tests/scenarios/{profinet,ethernetip,modbus,slmp}/ and the internal
matrices under docs/, then writes:

  docs/ctt_board_data.json
  (and embeds the same JSON into docs/ctt_board.html)

Classification mirrors CMakeLists.txt BUILD_CTT + default CI
`ctest -LE soak_ci`. This is a coverage board, not a live ctest run, and
not PI / ODVA / Modbus.org / Mitsubishi certification evidence.

Stdlib only (no PyYAML). Run from anywhere:

  python3 tools/ctt/gen_board_data.py
  python3 tools/ctt/gen_board_data.py --check
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCENARIO_ROOT = ROOT / "tests" / "scenarios"
PROTO_DIRS = ("profinet", "ethernetip", "modbus", "slmp")
JSON_OUT = ROOT / "docs" / "ctt_board_data.json"
HTML_OUT = ROOT / "docs" / "ctt_board.html"

STATUS_LABEL_KO = {
    "pass": "통과",
    "skip": "건너뜀",
    "gap": "갭",
    "out_of_scope": "범위 밖",
}

PROTOCOL_LABEL = {
    "profinet": "PROFINET",
    "ethernetip": "EtherNet/IP",
    "modbus_tcp": "Modbus TCP",
    "slmp": "SLMP",
    "other": "기타",
}

DIR_TO_PROTOCOL = {
    "profinet": "profinet",
    "ethernetip": "ethernetip",
    "modbus": "modbus_tcp",
    "slmp": "slmp",
}

CTEST_PREFIX = {
    "profinet": "ctt_pn_",
    "ethernetip": "ctt_eip_",
    "modbus_tcp": "ctt_mb_",
    "slmp": "ctt_slmp_",
}

MATRIX_FILES = {
    "profinet": ROOT / "docs" / "ctt_pi_matrix.md",
    "ethernetip": ROOT / "docs" / "ctt_odva_matrix.md",
    "modbus_tcp": ROOT / "docs" / "ctt_modbus_matrix.md",
    "slmp": ROOT / "docs" / "ctt_slmp_matrix.md",
}

# CMake GLOB is tests/scenarios/<proto>/*.yaml (not recursive).
CMAKE_TOPLEVEL_ONLY = True

DISCLAIMER_KO = (
    "내부 CTT 보드입니다. 내부 bundle-grade 게이트 ≠ PI / ODVA / Modbus.org / "
    "Mitsubishi 공식 인증. 배지는 시나리오가 기본 mock CI"
    "(`ctest -LE soak_ci`)에 등록되는지·매트릭스에 갭/범위 밖으로 적혀 "
    "있는지를 분류한 것이며, 이 페이지가 ctest 를 실행하지는 않습니다."
)

# Harness / product-scope rows that are not YAML and not a matrix table line.
HARNESS_ROWS = [
    {
        "id": "run_ctt_lab",
        "protocol": "profinet",
        "filename": "run_ctt_lab.sh",
        "path": "tests/run_ctt_lab.sh",
        "title": "veth AF_PACKET lab",
        "title_ko": "랩 (veth / AF_PACKET)",
        "description": (
            "같은 YAML 을 --transport=af_packet 로 돌린다. "
            "CAP_NET_RAW / CAP_NET_ADMIN. 기본 ctest 미등록. "
            "workflow_dispatch lab=true."
        ),
        "status": "skip",
        "reason": "opt-in lab; CAP_NET_RAW. CMake does not add_test this script.",
        "ctest_registered": False,
        "ci_default": False,
        "labels": ["lab"],
        "tags": ["lab", "af_packet"],
        "source": "docs/ctt_lab.md",
        "matrix": "docs/ctt_lab.md",
        "kind": "harness",
    },
    {
        "id": "codesys_manual_lab",
        "protocol": "profinet",
        "filename": "codesys_manual_lab.sh",
        "path": "tests/codesys_manual_lab.sh",
        "title": "CODESYS manual lab",
        "title_ko": "CODESYS 수동 랩",
        "description": "Windows Development System 은 CI 에 없다. 수동 랩만.",
        "status": "skip",
        "reason": "manual lab; not registered in ctest",
        "ctest_registered": False,
        "ci_default": False,
        "labels": ["lab"],
        "tags": ["lab", "codesys"],
        "source": "docs/ctt_lab.md",
        "matrix": "docs/ctt.md",
        "kind": "harness",
    },
    {
        "id": "ethercat",
        "protocol": "other",
        "filename": None,
        "path": None,
        "title": "EtherCAT",
        "title_ko": "EtherCAT",
        "description": "플러그인·시나리오 없음. 제품 CTT 범위 밖.",
        "status": "out_of_scope",
        "reason": "permanent non-goal (docs/ctt.md)",
        "ctest_registered": False,
        "ci_default": False,
        "labels": [],
        "tags": ["ethercat"],
        "source": "docs/ctt.md",
        "matrix": "docs/ctt.md",
        "kind": "matrix",
    },
    {
        "id": "cclink",
        "protocol": "other",
        "filename": None,
        "path": None,
        "title": "CC-Link",
        "title_ko": "CC-Link (스텁, 사양 미확정)",
        "description": "어댑터 스텁만. 사양 확정 전까지 CTT 시나리오 없음.",
        "status": "out_of_scope",
        "reason": "stub until spec is fixed (CLAUDE.md / docs/ctt.md)",
        "ctest_registered": False,
        "ci_default": False,
        "labels": [],
        "tags": ["cclink"],
        "source": "docs/ctt.md",
        "matrix": "docs/ctt.md",
        "kind": "matrix",
    },
]


def strip_md(s: str) -> str:
    s = s.strip()
    s = re.sub(r"\*\*([^*]+)\*\*", r"\1", s)
    s = re.sub(r"`([^`]+)`", r"\1", s)
    return s.strip()


def split_md_row(line: str) -> list[str]:
    """Split a markdown table row on `|`, keeping escaped `\\|` as a literal pipe."""
    body = line.strip().strip("|")
    cells = re.split(r"(?<!\\)\|", body)
    return [c.strip().replace("\\|", "|") for c in cells]


def parse_md_tables(path: Path) -> list[list[list[str]]]:
    if not path.is_file():
        return []
    tables: list[list[list[str]]] = []
    current: list[list[str]] | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line.startswith("|"):
            if current:
                tables.append(current)
                current = None
            continue
        cells = split_md_row(line)
        if cells and all(re.fullmatch(r":?-{3,}:?", c.replace(" ", "")) for c in cells):
            continue
        if current is None:
            current = [cells]
        else:
            current.append(cells)
    if current:
        tables.append(current)
    return tables


def yaml_name_from_cell(cell: str) -> str | None:
    m = re.search(r"([\w./-]+\.yaml)", cell)
    return m.group(1) if m else None


def classify_cover(cover: str) -> str | None:
    """Map a matrix '커버' cell to board status. None = covered by a YAML row."""
    c = cover.lower()
    if "dut not implemented" in c or "not yet" in c:
        return "gap"
    if "n/a" in c or "cc-c" in c:
        return "out_of_scope"
    return None


def matrix_lookup_key(protocol: str, filename: str) -> str:
    """Protocol-scoped key — soak_short.yaml exists in PN, Modbus, and SLMP."""
    return f"{protocol}::{Path(filename).name}"


def load_matrix_index() -> tuple[dict[str, dict], list[dict]]:
    """Return ((protocol, yaml_basename) -> meta, extra matrix rows without YAML)."""
    by_file: dict[str, dict] = {}
    extras: list[dict] = []
    seen_extra: set[str] = set()

    for protocol, path in MATRIX_FILES.items():
        rel = str(path.relative_to(ROOT))
        for table in parse_md_tables(path):
            if len(table) < 2:
                continue
            header = [h.lower() for h in table[0]]
            rows = table[1:]
            # YAML mapping tables have a first column that is a .yaml name.
            yamlish = sum(1 for r in rows if yaml_name_from_cell(r[0]))
            if yamlish >= max(1, len(rows) // 2):
                for row in rows:
                    fn = yaml_name_from_cell(row[0])
                    if not fn:
                        continue
                    base = Path(fn).name
                    category = strip_md(row[1]) if len(row) > 1 else ""
                    notes = strip_md(row[-1]) if len(row) > 2 else ""
                    mock = strip_md(row[2]) if len(row) > 2 else ""
                    by_file[matrix_lookup_key(protocol, base)] = {
                        "title": category,
                        "description": notes or mock,
                        "matrix": rel,
                        "protocol": protocol,
                        "mock": mock,
                    }
                continue

            # Category tables without a scenario file.
            for row in rows:
                if len(row) < 2:
                    continue
                category = strip_md(row[0])
                cover = strip_md(row[1])
                notes = strip_md(row[2]) if len(row) > 2 else ""
                status = classify_cover(cover)
                if not status:
                    continue
                key = f"{protocol}::{category.lower()}"
                if key in seen_extra:
                    continue
                seen_extra.add(key)
                slug = re.sub(r"[^a-z0-9]+", "_", category.lower()).strip("_")[:48]
                extras.append(
                    {
                        "id": f"matrix_{protocol}_{slug}",
                        "protocol": protocol,
                        "filename": None,
                        "path": None,
                        "title": category,
                        "title_ko": category,
                        "description": notes or cover,
                        "status": status,
                        "reason": f"{rel}: {cover}",
                        "ctest_name": None,
                        "ctest_registered": False,
                        "ci_default": False,
                        "labels": [],
                        "tags": [],
                        "source": rel,
                        "matrix": rel,
                        "kind": "matrix",
                        "cover": cover,
                    }
                )
    return by_file, extras


def parse_yaml_header(text: str) -> dict:
    name = None
    protocol = None
    bundle_id = None
    suite = None
    tags: list[str] = []
    for line in text.splitlines():
        if not line or line[0] in " \t":
            continue
        if line.startswith("name:"):
            name = line.split(":", 1)[1].strip().strip("'\"")
        elif line.startswith("protocol:"):
            protocol = line.split(":", 1)[1].strip().strip("'\"")
        elif line.startswith("bundle_id:"):
            bundle_id = line.split(":", 1)[1].strip().strip("'\"")
        elif line.startswith("id:"):
            # id: is the catalog TC id unless bundle_id: overrides.
            if not bundle_id:
                bundle_id = line.split(":", 1)[1].strip().strip("'\"")
        elif line.startswith("suite:"):
            suite = line.split(":", 1)[1].strip().strip("'\"")
        elif line.startswith("tags:"):
            inner = line.split(":", 1)[1].strip()
            m = re.match(r"\[(.*)\]", inner)
            if m:
                tags = [t.strip() for t in m.group(1).split(",") if t.strip()]
    return {
        "name": name,
        "protocol": protocol,
        "tags": tags,
        "bundle_id": bundle_id,
        "suite": suite,
    }


def cmake_registered(path: Path) -> bool:
    """Match CMake file(GLOB .../tests/scenarios/<proto>/*.yaml) — not nested."""
    try:
        rel = path.relative_to(SCENARIO_ROOT)
    except ValueError:
        return False
    parts = rel.parts
    if len(parts) != 2:
        return False
    return parts[0] in PROTO_DIRS and parts[1].endswith(".yaml")


def ctest_labels(protocol: str, sc_name: str, text: str, registered: bool) -> list[str]:
    """Mirror CMakeLists.txt set_tests_properties LABELS assignment."""
    if not registered:
        labels: list[str] = []
        if "nightly" in str(sc_name) or "/nightly/" in text:
            labels.append("nightly")
        return labels
    if protocol == "profinet":
        labels = []
        if sc_name == "soak_ci":
            labels = ["soak_ci"]
        if re.search(r"^\s*golden:", text, re.M):
            # CMake overwrites LABELS when golden: is present.
            labels = ["golden"]
        return labels
    if protocol == "modbus_tcp":
        return ["modbus"]
    if protocol == "slmp":
        return ["slmp"]
    if protocol == "ethernetip":
        return ["ethernetip"]
    return []


def classify_yaml(sc_name: str, tags: list[str], labels: list[str], registered: bool) -> tuple[str, str]:
    """Return (status, reason) for a scenario YAML."""
    if "lab" in tags:
        return "skip", "YAML tagged lab (CAP_NET_RAW / not default CI)"
    if sc_name == "soak_ci" or "soak_ci" in tags or "soak_ci" in labels:
        return (
            "skip",
            "opt-in 30s soak; default PR gate is ctest -LE soak_ci "
            "(LABELS soak_ci). workflow_dispatch soak=true.",
        )
    if not registered:
        return (
            "skip",
            "not globbed by CMake (subdirectory / nightly). "
            "Run ./build/ctt --scenario <path> manually.",
        )
    return "pass", "covered in default mock CI (ctest -LE soak_ci)"


def humanize(name: str) -> str:
    return name.replace("_", " ")


def collect_yaml_rows(matrix_by_file: dict[str, dict]) -> list[dict]:
    rows: list[dict] = []
    files = sorted(
        p
        for proto in PROTO_DIRS
        for p in (SCENARIO_ROOT / proto).rglob("*.yaml")
        if p.is_file()
    )
    for path in files:
        text = path.read_text(encoding="utf-8")
        header = parse_yaml_header(text)
        rel = str(path.relative_to(ROOT))
        proto_dir = path.relative_to(SCENARIO_ROOT).parts[0]
        protocol = header["protocol"] or DIR_TO_PROTOCOL[proto_dir]
        sc_name = header["name"] or path.stem
        tags = header["tags"]
        registered = cmake_registered(path)
        labels = ctest_labels(protocol, sc_name, text, registered)
        status, reason = classify_yaml(sc_name, tags, labels, registered)
        meta = matrix_by_file.get(matrix_lookup_key(protocol, path.name), {})
        title = meta.get("title") or humanize(sc_name)
        desc = meta.get("description") or ""
        ctest_name = None
        if registered:
            prefix = CTEST_PREFIX.get(protocol)
            if prefix:
                ctest_name = prefix + path.stem
        rows.append(
            {
                "id": sc_name,
                "bundle_id": header.get("bundle_id") or None,
                "suite": header.get("suite") or None,
                "protocol": protocol,
                "filename": path.name,
                "path": rel,
                "title": title,
                "title_ko": title,
                "description": desc,
                "status": status,
                "reason": reason,
                "ctest_name": ctest_name,
                "ctest_registered": registered,
                "ci_default": status == "pass",
                "labels": labels,
                "tags": tags,
                "source": "yaml",
                "matrix": meta.get("matrix"),
                "kind": "scenario",
                "golden": "golden" in labels,
            }
        )
    return rows


def finish_row(row: dict) -> dict:
    protocol = row["protocol"]
    status = row["status"]
    out = dict(row)
    out["protocol_label"] = PROTOCOL_LABEL.get(protocol, protocol)
    out["status_label_ko"] = STATUS_LABEL_KO[status]
    if not out.get("title_ko"):
        out["title_ko"] = out.get("title") or out.get("id")
    out.setdefault("ctest_name", None)
    out.setdefault("golden", False)
    out.setdefault("cover", None)
    out.setdefault("bundle_id", None)
    out.setdefault("suite", None)
    return out


def build_payload() -> dict:
    matrix_by_file, extras = load_matrix_index()
    tests = [finish_row(r) for r in collect_yaml_rows(matrix_by_file)]
    yaml_ids = {r["id"] for r in tests}
    yaml_files = {r["filename"] for r in tests}

    for extra in extras:
        if extra.get("filename") in yaml_files:
            continue
        tests.append(finish_row(extra))

    for harness in HARNESS_ROWS:
        if harness["id"] in yaml_ids:
            continue
        tests.append(finish_row(dict(harness)))

    order = {"pass": 0, "skip": 1, "gap": 2, "out_of_scope": 3}
    proto_order = {"profinet": 0, "ethernetip": 1, "modbus_tcp": 2, "slmp": 3, "other": 4}
    tests.sort(
        key=lambda r: (
            proto_order.get(r["protocol"], 9),
            order.get(r["status"], 9),
            r.get("path") or "",
            r["id"],
        )
    )

    counts = {k: 0 for k in STATUS_LABEL_KO}
    yaml_count = 0
    for t in tests:
        counts[t["status"]] = counts.get(t["status"], 0) + 1
        if t["kind"] == "scenario":
            yaml_count += 1
    counts["total"] = len(tests)
    counts["scenarios"] = yaml_count

    by_proto: dict[str, dict[str, int]] = {}
    for t in tests:
        bucket = by_proto.setdefault(
            t["protocol"], {k: 0 for k in ("pass", "skip", "gap", "out_of_scope", "total")}
        )
        bucket[t["status"]] += 1
        bucket["total"] += 1

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generator": "tools/ctt/gen_board_data.py",
        "disclaimer": DISCLAIMER_KO,
        "ci_default": "ctest --test-dir build --output-on-failure -LE soak_ci",
        "note": (
            "pass = YAML registered in CMake and included in default mock CI. "
            "skip = soak_ci / nightly / lab (opt-in). "
            "gap = matrix DUT-not-implemented or not-yet. "
            "out_of_scope = CC-C/IRT, official cert labs, EtherCAT, etc. "
            "Internal bundle-grade gate != PI / ODVA certification. "
            "PROFINET catalog: docs/ctt_pn_bundle.md (PN-B-* ids). "
            "EtherNet/IP catalog: docs/ctt_eip_bundle.md (EIP-A-* ids). "
            "Modbus TCP catalog: docs/ctt_mb_bundle.md (MB-T-* ids). "
            "SLMP Binary 3E catalog: docs/ctt_slmp_bundle.md (SLMP-3E-* ids)."
        ),
        "counts": counts,
        "by_protocol": by_proto,
        "tests": tests,
    }


def assert_invariants(data: dict) -> None:
    """Catch matrix key collisions and escaped-pipe truncation."""
    expected_matrix = {
        "profinet": "docs/ctt_pi_matrix.md",
        "ethernetip": "docs/ctt_odva_matrix.md",
        "modbus_tcp": "docs/ctt_modbus_matrix.md",
        "slmp": "docs/ctt_slmp_matrix.md",
    }
    soak_titles: dict[str, str] = {}
    for t in data["tests"]:
        if t["kind"] != "scenario":
            continue
        mx = t.get("matrix")
        want = expected_matrix.get(t["protocol"])
        if mx and want and mx != want:
            raise RuntimeError(
                f"{t['path']}: matrix {mx!r} does not belong to {t['protocol']}"
            )
        if t["id"] == "soak_short":
            soak_titles[t["protocol"]] = t["title"]
        if t["id"] == "fc22_mask_write":
            desc = t.get("description") or ""
            if "(cur & and)" not in desc or "(or & ~and)" not in desc:
                raise RuntimeError(f"fc22_mask_write description truncated: {desc!r}")
        if t["protocol"] == "profinet" and t["kind"] == "scenario":
            bid = t.get("bundle_id") or ""
            if not re.fullmatch(r"PN-B-[A-Z]+-\d{3}", bid):
                raise RuntimeError(
                    f"{t['path']}: missing/invalid bundle_id {bid!r} "
                    "(expect PN-B-AREA-NNN; see docs/ctt_pn_bundle.md)"
                )
        if t["protocol"] == "ethernetip" and t["kind"] == "scenario":
            bid = t.get("bundle_id") or ""
            if not re.fullmatch(r"EIP-A-[A-Z]+-\d{3}", bid):
                raise RuntimeError(
                    f"{t['path']}: missing/invalid bundle_id {bid!r} "
                    "(expect EIP-A-AREA-NNN; see docs/ctt_eip_bundle.md)"
                )
        if t["protocol"] == "modbus_tcp" and t["kind"] == "scenario":
            bid = t.get("bundle_id") or ""
            if not re.fullmatch(r"MB-T-[A-Z]+-\d{3}", bid):
                raise RuntimeError(
                    f"{t['path']}: missing/invalid bundle_id {bid!r} "
                    "(expect MB-T-AREA-NNN; see docs/ctt_mb_bundle.md)"
                )
        if t["protocol"] == "slmp" and t["kind"] == "scenario":
            bid = t.get("bundle_id") or ""
            if not re.fullmatch(r"SLMP-3E-[A-Z]+-\d{3}", bid):
                raise RuntimeError(
                    f"{t['path']}: missing/invalid bundle_id {bid!r} "
                    "(expect SLMP-3E-AREA-NNN; see docs/ctt_slmp_bundle.md)"
                )
    if len(soak_titles) >= 2 and len(set(soak_titles.values())) < len(soak_titles):
        raise RuntimeError(f"soak_short titles collided across protocols: {soak_titles}")


EMBED_BEGIN = "<!-- CTT_BOARD_DATA_BEGIN -->"
EMBED_END = "<!-- CTT_BOARD_DATA_END -->"


def embed_in_html(data: dict) -> None:
    if not HTML_OUT.is_file():
        print(f"warn: {HTML_OUT} missing; JSON only", file=sys.stderr)
        return
    html = HTML_OUT.read_text(encoding="utf-8")
    blob = json.dumps(data, ensure_ascii=False, indent=2)
    # Avoid accidental </script> termination if a string ever contains it.
    blob = blob.replace("</", "<\\/")
    block = (
        f"{EMBED_BEGIN}\n"
        f'<script type="application/json" id="ctt-board-data">\n'
        f"{blob}\n"
        f"</script>\n"
        f"{EMBED_END}"
    )
    if EMBED_BEGIN in html and EMBED_END in html:
        pre, rest = html.split(EMBED_BEGIN, 1)
        _, post = rest.split(EMBED_END, 1)
        html = pre + block + post
    else:
        # Insert before </body> if markers are absent.
        html = html.replace("</body>", block + "\n</body>")
    HTML_OUT.write_text(html, encoding="utf-8")


def write_json(data: dict) -> None:
    JSON_OUT.parent.mkdir(parents=True, exist_ok=True)
    JSON_OUT.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def payload_for_compare(data: dict) -> dict:
    slim = dict(data)
    slim.pop("generated_at", None)
    return slim


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate docs/ctt_board_data.json")
    ap.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if committed JSON (ignoring generated_at) is stale",
    )
    args = ap.parse_args()
    data = build_payload()
    assert_invariants(data)

    if args.check:
        if not JSON_OUT.is_file():
            print(f"missing {JSON_OUT}", file=sys.stderr)
            return 1
        old = json.loads(JSON_OUT.read_text(encoding="utf-8"))
        if payload_for_compare(old) != payload_for_compare(data):
            print("docs/ctt_board_data.json is stale; re-run tools/ctt/gen_board_data.py")
            return 1
        print("docs/ctt_board_data.json is up to date")
        return 0

    write_json(data)
    embed_in_html(data)
    c = data["counts"]
    print(
        f"wrote {JSON_OUT.relative_to(ROOT)}  "
        f"pass={c['pass']} skip={c['skip']} gap={c['gap']} "
        f"oos={c['out_of_scope']} total={c['total']} "
        f"(yaml={c['scenarios']})"
    )
    yaml_pass = sum(
        1 for t in data["tests"] if t["kind"] == "scenario" and t["status"] == "pass"
    )
    yaml_skip = sum(
        1 for t in data["tests"] if t["kind"] == "scenario" and t["status"] == "skip"
    )
    print(f"yaml scenarios: pass={yaml_pass} skip={yaml_skip}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
