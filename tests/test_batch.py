"""Batch (multi-target) scanning via --targets."""

from __future__ import annotations

import json

from scanner import cli


def test_batch_json_and_reports(app_url, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    targets = tmp_path / "targets.txt"
    targets.write_text(
        f"# comment line\n{app_url}\n{app_url}   # duplicate is deduped\n",
        encoding="utf-8",
    )
    rc = cli.main(["--targets", str(targets), "--allow-private",
                   "--modules", "headers", "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["meta"]["targets"] == 1          # duplicate collapsed
    assert len(data["targets"]) == 1
    assert data["meta"]["total_findings"] >= 1
    # summary + per-target reports were written under reports/
    reports = list((tmp_path / "reports").glob("batch_*.html"))
    summaries = list((tmp_path / "reports").glob("batch_*.json"))
    per_target = list((tmp_path / "reports").glob("scan_*.html"))
    assert reports and summaries and per_target


def test_batch_gate_aggregates_targets(app_url, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    targets = tmp_path / "targets.txt"
    targets.write_text(f"{app_url}\n", encoding="utf-8")
    rc = cli.main(["--targets", str(targets), "--allow-private",
                   "--modules", "cmdi", "--fail-on", "critical", "--no-report",
                   "--format", "json"])
    assert rc == 1                                # cmdi is critical on /ping


def test_batch_rejects_single_target_options(app_url, tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text(f"{app_url}\n", encoding="utf-8")
    rc = cli.main(["--targets", str(targets), "--allow-private",
                   "--sarif", "x.sarif", "--no-report"])
    assert rc == 2


def test_batch_empty_file_is_error(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("# only comments\n", encoding="utf-8")
    rc = cli.main(["--targets", str(targets), "--allow-private", "--no-report"])
    assert rc == 2


def test_url_and_targets_are_mutually_exclusive(app_url, tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text(f"{app_url}\n", encoding="utf-8")
    try:
        cli.main(["-u", app_url, "--targets", str(targets), "--no-report"])
        raised = False
    except SystemExit:
        raised = True
    assert raised
