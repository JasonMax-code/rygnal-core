"""Run Rygnal real workflow scenarios."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from demo.cli_output import render_run_report  # noqa: E402
from demo.scenario_runner import ScenarioRunner  # noqa: E402


def main() -> None:
    """Run all Rygnal real workflow scenarios."""
    runner = ScenarioRunner()
    outcomes = runner.run_all()
    print(render_run_report(outcomes))


if __name__ == "__main__":
    main()
