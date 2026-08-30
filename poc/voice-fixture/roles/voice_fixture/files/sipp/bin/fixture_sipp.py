#!/usr/bin/env python3
"""Run bounded SIPp fixtures with an RTP counter/echo endpoint.

The executable accepts only the fixed POC addresses and ports. Network policy
is also enforced outside the container by the owning systemd cgroup.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Union


CONTROLLER_IP = ipaddress.ip_address("10.20.1.4")
EDGE_NETWORK = ipaddress.ip_network("10.20.2.0/24")
EDGE_IPS = {ipaddress.ip_address("10.20.2.4"), ipaddress.ip_address("10.20.2.5")}
EDGE_SERVER_NAMES = {
    ipaddress.ip_address("10.20.2.4"): "sbc1.voice.vivolution.ae",
    ipaddress.ip_address("10.20.2.5"): "sbc2.voice.vivolution.ae",
}
UAS_TLS_PORT = 25061
UAC_TLS_PORT = 25062
TLS_PROBE_PORT = 25063
UAS_RTP_PORT = 22000
UAC_RTP_PORT = 22032
TEST_ID_RE = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z_.-]{0,63}\Z")


def is_valid_rtp(packet: bytes) -> bool:
    """Accept a minimally well-formed RTPv2 fixed header."""
    return len(packet) >= 12 and packet[0] >> 6 == 2


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, sort_keys=True, indent=2) + "\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(encoded, encoding="utf-8")
    os.chmod(temporary, 0o640)
    os.replace(temporary, path)


class RtpProbe:
    def __init__(
        self,
        *,
        bind_ip: ipaddress.IPv4Address,
        bind_port: int,
        output: Path,
        allowed_sources: Union[set[ipaddress.IPv4Address], ipaddress.IPv4Network],
    ) -> None:
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.output = output
        self.allowed_sources = allowed_sources
        self.started_at = time.time()
        self.packets_received = 0
        self.packets_echoed = 0
        self.bytes_received = 0
        self.invalid_packets = 0
        self.rejected_sources = 0
        self.sources: dict[str, int] = {}
        self._stop = threading.Event()
        self.ready = threading.Event()
        self._thread = threading.Thread(target=self._run, name="fixture-rtp", daemon=True)

    def start(self) -> None:
        self._thread.start()
        if not self.ready.wait(timeout=5):
            raise RuntimeError("RTP probe did not bind within five seconds")

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=3)
        self._write()

    def snapshot(self) -> dict[str, Any]:
        return {
            "bind": f"{self.bind_ip}:{self.bind_port}",
            "bytes_received": self.bytes_received,
            "updated_at_unix": int(time.time()),
            "invalid_packets": self.invalid_packets,
            "packets_echoed": self.packets_echoed,
            "packets_received": self.packets_received,
            "rejected_sources": self.rejected_sources,
            "sources": dict(sorted(self.sources.items())),
            "started_at_unix": int(self.started_at),
        }

    def _write(self) -> None:
        atomic_json(self.output, self.snapshot())

    def _source_allowed(self, source: ipaddress.IPv4Address) -> bool:
        if isinstance(self.allowed_sources, set):
            return source in self.allowed_sources
        return source in self.allowed_sources

    def _run(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            listener.bind((str(self.bind_ip), self.bind_port))
            listener.settimeout(0.5)
            self.ready.set()
            self._write()
            while not self._stop.is_set():
                try:
                    packet, peer = listener.recvfrom(8192)
                except TimeoutError:
                    continue
                source = ipaddress.ip_address(peer[0])
                if not isinstance(source, ipaddress.IPv4Address) or not self._source_allowed(source):
                    self.rejected_sources += 1
                    self._write()
                    continue
                if not is_valid_rtp(packet):
                    self.invalid_packets += 1
                    self._write()
                    continue
                self.packets_received += 1
                self.bytes_received += len(packet)
                self.sources[str(source)] = self.sources.get(str(source), 0) + 1
                listener.sendto(packet, peer)
                self.packets_echoed += 1
                self._write()


def common_sipp_args(
    *, bind_port: int, scenario: str, stats: Union[Path, None], errors: Path, ca_file: str
) -> list[str]:
    arguments = [
        "/usr/bin/sipp",
        "-sf",
        scenario,
        "-i",
        str(CONTROLLER_IP),
        "-bind_local",
        "-p",
        str(bind_port),
        "-ci",
        "127.0.0.1",
        "-nostdin",
        "-t",
        "l1",
        "-tls_cert",
        "/run/fixture-pki/sipp.crt",
        "-tls_key",
        "/run/fixture-pki/sipp.key",
        "-tls_ca",
        ca_file,
        "-tls_version",
        "1.2",
        "-l",
        "1",
        "-recv_timeout",
        "10000",
        "-trace_err",
        "-error_file",
        str(errors),
        "-max_log_size",
        "10485760",
    ]
    if stats is not None:
        arguments.extend(["-trace_stat", "-stf", str(stats)])
    return arguments


def run_uas() -> int:
    output = Path("/results/runtime/teams-uas-rtp.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    probe = RtpProbe(
        bind_ip=CONTROLLER_IP,
        bind_port=UAS_RTP_PORT,
        output=output,
        allowed_sources=EDGE_IPS,
    )
    command = common_sipp_args(
        bind_port=UAS_TLS_PORT,
        scenario="/opt/fixture/scenarios/teams-uas.xml",
        # Periodic SIPp statistics are intentionally disabled for this
        # long-running UAS; the bounded error log, RTP counter, per-test CDR,
        # and journal window provide its evidence without unbounded growth.
        stats=None,
        errors=Path("/results/runtime/teams-uas-errors.log"),
        ca_file="/run/fixture-pki/ca.crt",
    )
    probe.start()
    process = subprocess.Popen(command)

    def stop(_signum: int, _frame: object) -> None:
        if process.poll() is None:
            process.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        return process.wait()
    finally:
        probe.stop()


def ensure_results_root(path: Path) -> Path:
    resolved = path.resolve()
    root = Path("/results").resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError("result path must remain below /results")
    return resolved


def verify_edge_server(
    *, server_name: str, expected_ip: ipaddress.IPv4Address, server_port: int
) -> str:
    """Verify public Edge TLS identity without DNS or public-IP hairpinning."""
    resolved = {
        ipaddress.ip_address(item[4][0])
        for item in socket.getaddrinfo(server_name, server_port, socket.AF_INET, socket.SOCK_STREAM)
    }
    if resolved != {expected_ip}:
        raise ValueError(
            f"static Edge mapping drift for {server_name}: expected {expected_ip}, got {sorted(map(str, resolved))}"
        )
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH, cafile="/run/fixture-pki/public-ca.crt"
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        certfile="/run/fixture-pki/sipp.crt", keyfile="/run/fixture-pki/sipp.key"
    )
    with socket.create_connection(
        (server_name, server_port),
        timeout=5,
        source_address=(str(CONTROLLER_IP), TLS_PROBE_PORT),
    ) as transport:
        with context.wrap_socket(transport, server_hostname=server_name) as tls_socket:
            peer_certificate = tls_socket.getpeercert(binary_form=True)
    if not peer_certificate:
        raise ssl.SSLError("Edge did not present a server certificate")
    return hashlib.sha256(peer_certificate).hexdigest()


def run_uac(args: argparse.Namespace) -> int:
    target = ipaddress.ip_address(args.target_ip)
    if target not in EDGE_IPS:
        raise ValueError("target must be the fixed SBC1 or SBC2 private address")
    if args.target_port != 5061:
        raise ValueError("synthetic Teams calls must target Edge TLS 5061")
    if not TEST_ID_RE.fullmatch(args.test_id):
        raise ValueError("invalid bounded test ID")

    output_dir = ensure_results_root(Path(args.output_dir))
    output_dir.mkdir(parents=True, exist_ok=True)
    rtp_output = output_dir / "teams-to-pbx-rtp.json"
    probe = RtpProbe(
        bind_ip=CONTROLLER_IP,
        bind_port=UAC_RTP_PORT,
        output=rtp_output,
        allowed_sources={target},
    )
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix="fixture-", suffix=".csv", delete=False
    ) as injection:
        injection.write("SEQUENTIAL\n")
        injection.write(f"{args.test_id};\n")
        injection_path = Path(injection.name)

    command = common_sipp_args(
        bind_port=UAC_TLS_PORT,
        scenario="/opt/fixture/scenarios/teams-uac.xml",
        stats=output_dir / "teams-to-pbx-sipp-stats.csv",
        errors=output_dir / "teams-to-pbx-sipp-errors.log",
        ca_file="/run/fixture-pki/public-ca.crt",
    )
    server_name = EDGE_SERVER_NAMES[target]
    edge_certificate_sha256 = verify_edge_server(
        server_name=server_name,
        expected_ip=target,
        server_port=args.target_port,
    )
    command.insert(1, f"{server_name}:{args.target_port}")
    command.extend(
        [
            "-inf",
            str(injection_path),
            "-m",
            "1",
            "-r",
            "1",
            "-timeout",
            "25s",
            "-timeout_error",
        ]
    )
    probe.start()
    try:
        completed = subprocess.run(command, check=False)
    finally:
        probe.stop()
        injection_path.unlink(missing_ok=True)
    summary = probe.snapshot()
    summary["sipp_exit_code"] = completed.returncode
    summary["edge_server_certificate_sha256"] = edge_certificate_sha256
    summary["target"] = f"{server_name}({target}):{args.target_port}"
    summary["test_id"] = args.test_id
    atomic_json(output_dir / "teams-to-pbx-summary.json", summary)
    if completed.returncode != 0:
        return completed.returncode
    if summary["packets_received"] < 1 or summary["packets_echoed"] < 1:
        print("no valid RTP reached the Teams-side UAC fixture", file=sys.stderr)
        return 20
    if summary["invalid_packets"] or summary["rejected_sources"]:
        print("unexpected RTP input reached the Teams-side UAC fixture", file=sys.stderr)
        return 21
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="mode", required=True)
    subparsers.add_parser("uas")
    uac = subparsers.add_parser("uac")
    uac.add_argument("--target-ip", required=True)
    uac.add_argument("--target-port", required=True, type=int)
    uac.add_argument("--test-id", required=True)
    uac.add_argument("--output-dir", default="/results")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.mode == "uas":
            return run_uas()
        return run_uac(args)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"fixture error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
