from __future__ import annotations

import os
import pathlib
import shlex
import subprocess
import sys
import tempfile
import textwrap
import unittest

SAMPLER = pathlib.Path(__file__).with_name("resource-sampler.sh")


class ResourceSamplerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.directory = pathlib.Path(self.temp.name)
        self.bin_directory = self.directory / "bin"
        self.bin_directory.mkdir()
        self.clock = self.directory / "clock-ns"
        self.clock.write_text("1000000000\n", encoding="utf-8")
        self.sleep_log = self.directory / "sleep-log"

        self.write_command(
            "date",
            """
            import os
            import pathlib

            clock = pathlib.Path(os.environ["FAKE_CLOCK_FILE"])
            now = int(clock.read_text(encoding="utf-8"))
            now += int(os.environ["FAKE_DATE_OVERHEAD_NS"])
            clock.write_text(f"{now}\\n", encoding="utf-8")
            print(now)
            """,
        )
        self.write_command(
            "sleep",
            """
            import decimal
            import os
            import pathlib
            import sys

            clock = pathlib.Path(os.environ["FAKE_CLOCK_FILE"])
            now = int(clock.read_text(encoding="utf-8"))
            delay = int(decimal.Decimal(sys.argv[1]) * 1_000_000_000)
            clock.write_text(f"{now + delay}\\n", encoding="utf-8")
            with pathlib.Path(os.environ["FAKE_SLEEP_LOG"]).open(
                "a", encoding="utf-8"
            ) as stream:
                stream.write(f"{sys.argv[1]}\\n")
            """,
        )
        self.write_command(
            "systemctl",
            """
            import sys

            if "--property=MemoryCurrent" in sys.argv:
                print(1048576)
            elif "--property=CPUUsageNSec" in sys.argv:
                print(1000000000)
            else:
                raise SystemExit(2)
            """,
        )
        self.write_command(
            "awk",
            """
            print(2097152)
            """,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_command(self, name: str, source: str) -> None:
        source_path = self.bin_directory / f"{name}.py"
        source_path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
        path = self.bin_directory / name
        path.write_text(
            "#!/bin/sh\n"
            f"exec {shlex.quote(sys.executable)} {shlex.quote(str(source_path))} \"$@\"\n",
            encoding="utf-8",
        )
        path.chmod(0o700)

    def run_sampler(self, date_overhead_ns: int) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "CP_RESOURCE_DURATION_SECONDS": "5",
                "FAKE_CLOCK_FILE": str(self.clock),
                "FAKE_DATE_OVERHEAD_NS": str(date_overhead_ns),
                "FAKE_SLEEP_LOG": str(self.sleep_log),
                "PATH": str(self.bin_directory),
            }
        )
        return subprocess.run(
            ["/bin/sh", str(SAMPLER)],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
        )

    def test_sampler_compensates_for_collection_overhead(self) -> None:
        result = self.run_sampler(200000000)

        self.assertEqual(result.returncode, 0, result.stderr)
        metrics = dict(line.split(": ", 1) for line in result.stdout.splitlines())
        self.assertEqual(metrics["duration_seconds"], "5")
        self.assertEqual(metrics["samples"], "5")
        self.assertEqual(metrics["elapsed_sample_ns"], "4000000000")

        waits = self.sleep_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(waits, ["0.400000000"] * 5)

    def test_sampler_does_not_backfill_missed_slots(self) -> None:
        result = self.run_sampler(600000000)

        self.assertEqual(result.returncode, 0, result.stderr)
        metrics = dict(line.split(": ", 1) for line in result.stdout.splitlines())
        self.assertEqual(metrics["duration_seconds"], "5")
        self.assertEqual(metrics["samples"], "3")
        self.assertEqual(metrics["elapsed_sample_ns"], "4000000000")


if __name__ == "__main__":
    unittest.main()
