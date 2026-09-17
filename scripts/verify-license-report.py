#!/usr/bin/env python3
"""Fail-closed reconciliation of Goneat licenses against the full Go graph."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

KNOWN_DEGRADATION = {
    "Type": "license",
    "Severity": "medium",
    "Message": "License detection degraded: some errors occurred when loading direct and transitive dependency packages",
    "Dependency": None,
}
EXPECTED_SCOPE = {
    "module_graph": "go list -m -json all",
    "goneat_runtime": "go list -deps -json ./...",
}


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read JSON {path}: {exc}")


def decode_stream(text: str) -> list[dict[str, object]]:
    decoder = json.JSONDecoder()
    values: list[dict[str, object]] = []
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        value, offset = decoder.raw_decode(text, offset)
        if not isinstance(value, dict):
            fail("go list emitted a non-object value")
        values.append(value)
    return values


def go_list(go_bin: str, *args: str) -> list[dict[str, object]]:
    try:
        result = subprocess.run(
            [go_bin, *args], check=True, capture_output=True, text=True
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"{' '.join((go_bin, *args))} failed: {exc}")
    return decode_stream(result.stdout)


def module_tuple(value: dict[str, object]) -> tuple[str, str]:
    path = value.get("Path")
    version = value.get("Version", "")
    if not isinstance(path, str) or not isinstance(version, str):
        fail(f"invalid module identity: {value!r}")
    return path, version


def main() -> None:
    if len(sys.argv) not in (2, 3):
        print("usage: verify-license-report.py REPORT [BASELINE]", file=sys.stderr)
        raise SystemExit(2)

    report_path = Path(sys.argv[1])
    baseline_path = Path(
        sys.argv[2] if len(sys.argv) == 3 else ".goneat/license-baseline.json"
    )
    report = load_json(report_path)
    baseline = load_json(baseline_path)
    if not isinstance(report, dict) or not isinstance(baseline, dict):
        fail("report and baseline must be JSON objects")

    if baseline.get("scope") != EXPECTED_SCOPE:
        fail(
            "baseline scope must explicitly bind the full module graph and "
            "Goneat runtime reconciliation commands"
        )

    allowed = baseline.get("allowed_licenses")
    modules = baseline.get("modules")
    if (
        not isinstance(allowed, list)
        or not allowed
        or not all(isinstance(item, str) and item for item in allowed)
    ):
        fail("baseline allowed_licenses must be a nonempty string list")
    if len(allowed) != len(set(allowed)):
        fail("baseline allowed_licenses contains duplicates")
    if not isinstance(modules, list) or not modules:
        fail("baseline modules must be a nonempty list")

    detector_version = os.environ.get("DECERNOR_GONEAT_VERSION", "")
    if not detector_version:
        fail("DECERNOR_GONEAT_VERSION must identify the Goneat detector")

    baseline_by_id: dict[tuple[str, str], str] = {}
    goneat_license_by_id: dict[tuple[str, str], str] = {}
    for module in modules:
        if not isinstance(module, dict):
            fail(f"invalid baseline module: {module!r}")
        path = module.get("path")
        version = module.get("version")
        license_id = module.get("license")
        if not all(isinstance(item, str) for item in (path, version, license_id)):
            fail(f"invalid baseline module fields: {module!r}")
        if not path or not license_id:
            fail(f"empty path or license in baseline: {module!r}")
        if license_id not in allowed:
            fail(f"module {path}@{version} uses disallowed license {license_id}")
        identity = (path, version)
        if identity in baseline_by_id:
            fail(f"duplicate baseline module {path}@{version}")
        baseline_by_id[identity] = license_id
        goneat = module.get("goneat")
        if goneat is None:
            goneat_license_by_id[identity] = license_id
        elif isinstance(goneat, dict):
            goneat_version = goneat.get("version")
            goneat_license = goneat.get("license")
            if not isinstance(goneat_version, str) or not isinstance(
                goneat_license, str
            ):
                fail(f"invalid Goneat alias for {path}@{version}: {goneat!r}")
            if goneat_version != detector_version:
                fail(
                    f"Goneat alias for {path}@{version} is pinned to {goneat_version}, "
                    f"but detector is {detector_version}"
                )
            if not goneat_license:
                fail(f"empty Goneat license alias for {path}@{version}")
            if goneat_license not in allowed:
                fail(
                    f"Goneat license alias for {path}@{version} is not allowed: "
                    f"{goneat_license}"
                )
            goneat_license_by_id[identity] = goneat_license
        else:
            fail(f"invalid Goneat alias for {path}@{version}: {goneat!r}")

    go_bin = os.environ.get("DECERNOR_LICENSE_GO", "go")
    graph = {
        module_tuple(item) for item in go_list(go_bin, "list", "-m", "-json", "all")
    }
    expected = set(baseline_by_id)
    if graph != expected:
        missing = sorted(graph - expected)
        extra = sorted(expected - graph)
        fail(
            f"license baseline does not match go list -m all; missing={missing}, extra={extra}"
        )

    runtime: set[tuple[str, str]] = set()
    for package in go_list(go_bin, "list", "-deps", "-json", "./..."):
        module = package.get("Module")
        if isinstance(module, dict):
            runtime.add(module_tuple(module))

    dependencies = report.get("Dependencies")
    if not isinstance(dependencies, list):
        fail("Goneat report Dependencies must be a list")
    reported: dict[tuple[str, str], str] = {}
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            fail(f"invalid Goneat dependency: {dependency!r}")
        name = dependency.get("Name")
        version = dependency.get("Version", "")
        license_value = dependency.get("License")
        license_id = (
            license_value.get("Type") if isinstance(license_value, dict) else None
        )
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or not isinstance(license_id, str)
        ):
            fail(f"invalid Goneat dependency fields: {dependency!r}")
        identity = (name, version)
        if identity in reported:
            fail(f"duplicate Goneat dependency {name}@{version}")
        reported[identity] = license_id

    if set(reported) != runtime:
        missing = sorted(runtime - set(reported))
        extra = sorted(set(reported) - runtime)
        fail(f"Goneat runtime coverage mismatch; missing={missing}, extra={extra}")
    for identity, license_id in reported.items():
        expected_license = goneat_license_by_id.get(identity)
        if license_id != expected_license:
            fail(
                f"Goneat license mismatch for {identity[0]}@{identity[1]}: "
                f"report={license_id!r}, baseline={expected_license!r}"
            )

    if report.get("Passed") is not True:
        fail("Goneat report did not pass its configured policy")
    issues = report.get("Issues")
    if not isinstance(issues, list):
        fail("Goneat report Issues must be a list")
    if issues not in ([], [KNOWN_DEGRADATION]):
        fail(f"Goneat report contains unexpected issues: {issues!r}")

    for path, version in sorted(expected):
        print(
            f"[ok] license {path}@{version or '(main)'}: {baseline_by_id[(path, version)]}"
        )
    if issues:
        print(
            "[ok] exact known stdlib degradation accepted after complete graph coverage"
        )
    print("[ok] full module graph and Goneat runtime license report reconcile")


if __name__ == "__main__":
    main()
