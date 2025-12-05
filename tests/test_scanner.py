from click.testing import CliRunner

from package_scan.cli import cli


def test_cli_help():
    """Test the CLI with the --help option."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "package-scan" in result.output.lower() or "scan" in result.output.lower()
    assert "--dir" in result.output
    assert "--ecosystem" in result.output


def test_list_ecosystems():
    """Test the --list-ecosystems option."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--list-ecosystems"])
    assert result.exit_code == 0
    assert "npm" in result.output
    assert "maven" in result.output
    assert "pip" in result.output
