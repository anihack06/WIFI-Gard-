from __future__ import annotations

from io import StringIO
from pathlib import Path

from rich.console import Console

import wifiguard_auditor.cli as cli


def test_resolve_wordlist_path_prefers_explicit_over_defaults(tmp_path: Path) -> None:
    current_directory = tmp_path / "cwd"
    project_root = tmp_path / "repo"
    current_directory.mkdir()
    project_root.mkdir()

    explicit = tmp_path / "custom.txt"
    explicit.write_text("alpha\n", encoding="utf-8")
    (current_directory / cli.DEFAULT_WORDLIST_NAME).write_text("cwd\n", encoding="utf-8")
    (project_root / cli.DEFAULT_WORDLIST_NAME).write_text("repo\n", encoding="utf-8")

    resolved = cli._resolve_wordlist_path(
        str(explicit),
        cwd=current_directory,
        project_root=project_root,
    )

    assert resolved == explicit.resolve()


def test_resolve_wordlist_path_uses_current_directory_first(tmp_path: Path) -> None:
    current_directory = tmp_path / "cwd"
    project_root = tmp_path / "repo"
    current_directory.mkdir()
    project_root.mkdir()

    cwd_wordlist = current_directory / cli.DEFAULT_WORDLIST_NAME
    repo_wordlist = project_root / cli.DEFAULT_WORDLIST_NAME
    cwd_wordlist.write_text("cwd\n", encoding="utf-8")
    repo_wordlist.write_text("repo\n", encoding="utf-8")

    resolved = cli._resolve_wordlist_path(None, cwd=current_directory, project_root=project_root)

    assert resolved == cwd_wordlist.resolve()


def test_resolve_wordlist_path_falls_back_to_project_root(tmp_path: Path) -> None:
    current_directory = tmp_path / "cwd"
    project_root = tmp_path / "repo"
    current_directory.mkdir()
    project_root.mkdir()

    repo_wordlist = project_root / cli.DEFAULT_WORDLIST_NAME
    repo_wordlist.write_text("repo\n", encoding="utf-8")

    resolved = cli._resolve_wordlist_path(None, cwd=current_directory, project_root=project_root)

    assert resolved == repo_wordlist.resolve()


def test_resolve_wordlist_path_returns_none_when_no_default_exists(tmp_path: Path) -> None:
    current_directory = tmp_path / "cwd"
    project_root = tmp_path / "repo"
    current_directory.mkdir()
    project_root.mkdir()

    resolved = cli._resolve_wordlist_path(None, cwd=current_directory, project_root=project_root)

    assert resolved is None


def test_audit_passphrase_uses_default_wordlist_and_surfaces_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    current_directory = tmp_path / "cwd"
    project_root = tmp_path / "repo"
    current_directory.mkdir()
    project_root.mkdir()

    default_wordlist = project_root / cli.DEFAULT_WORDLIST_NAME
    default_wordlist.write_text("password\n", encoding="utf-8")
    report_path = tmp_path / "audit-report.txt"

    console_buffer = StringIO()
    console = Console(file=console_buffer, force_terminal=False, color_system=None, width=120)
    monkeypatch.setattr(cli, "build_console", lambda: console)
    monkeypatch.setattr(cli, "PROJECT_ROOT", project_root)
    monkeypatch.chdir(current_directory)

    exit_code = cli.main(
        [
            "audit-passphrase",
            "--known-password",
            "password",
            "--report",
            str(report_path),
        ]
    )

    assert exit_code == 0
    assert "Using default wordlist:" in console_buffer.getvalue()
    assert str(default_wordlist.resolve()) in console_buffer.getvalue()

    report_text = report_path.read_text(encoding="utf-8")
    assert f"Wordlist Path: {default_wordlist.resolve()}" in report_text
    assert "Found In Wordlist: Yes" in report_text


def test_audit_passphrase_falls_back_to_strength_only_without_default_wordlist(
    tmp_path: Path,
    monkeypatch,
) -> None:
    current_directory = tmp_path / "cwd"
    project_root = tmp_path / "repo"
    current_directory.mkdir()
    project_root.mkdir()

    report_path = tmp_path / "audit-report.txt"

    console_buffer = StringIO()
    console = Console(file=console_buffer, force_terminal=False, color_system=None, width=120)
    monkeypatch.setattr(cli, "build_console", lambda: console)
    monkeypatch.setattr(cli, "PROJECT_ROOT", project_root)
    monkeypatch.chdir(current_directory)

    exit_code = cli.main(
        [
            "audit-passphrase",
            "--known-password",
            "Taller!River!Lantern!27",
            "--report",
            str(report_path),
        ]
    )

    assert exit_code == 0
    assert "Using default wordlist:" not in console_buffer.getvalue()

    report_text = report_path.read_text(encoding="utf-8")
    assert "Wordlist Checked: No" in report_text
    assert "Wordlist Path:" not in report_text
