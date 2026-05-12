"""Tests for the unified `agenticqa` CLI dispatcher."""

from __future__ import annotations

from agenticqa_core import __version__, cli


def test_cli_no_args_prints_help(capsys):
    rc = cli.main([])
    assert rc == 0
    out = capsys.readouterr().out
    assert "agenticqa" in out
    assert "probe-headers" in out
    assert "audit-app" in out


def test_cli_help_flag(capsys):
    assert cli.main(["--help"]) == 0
    assert "probe-headers" in capsys.readouterr().out


def test_cli_version_flag(capsys):
    rc = cli.main(["--version"])
    assert rc == 0
    assert capsys.readouterr().out.strip() == __version__


def test_cli_unknown_command_errors(capsys):
    rc = cli.main(["does-not-exist"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "unknown command" in err


def test_cli_dispatches_to_subcommand_help(capsys):
    rc = cli.main(["probe-headers", "--help"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "usage" in out


def test_cli_command_registry_matches_modules():
    for cmd, (mod_name, _desc) in cli.COMMANDS.items():
        # Each command name is hyphenated; module path is dotted.
        assert "." in mod_name
        assert isinstance(cmd, str)
