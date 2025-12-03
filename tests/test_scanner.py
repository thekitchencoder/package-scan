from click.testing import CliRunner
from hulud_scan.scan_npm_threats import cli


def test_cli_help():
    """Test the CLI with the --help option."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Usage: npm-scan [OPTIONS]" in result.output
