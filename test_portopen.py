import contextlib
import io
import json
import socket
import threading
import time
import unittest
from unittest import mock

import portopen
from portopen import CLOSED, ERROR, FILTERED, OPEN, Result


class Listener:
    """A local TCP server that optionally greets each client with a banner."""

    def __init__(self, greeting=b""):
        self.greeting = greeting
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            with conn:
                if self.greeting:
                    conn.sendall(self.greeting)

    def close(self):
        self.running = False
        self.thread.join()
        self.sock.close()


def closed_port():
    """A port that is bound but not listening, so connections are refused."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    return sock, sock.getsockname()[1]


def run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = portopen.main(list(argv))
    return code, out.getvalue()


class ParseTests(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(portopen.parse_ports("22,80,8000-8002,80"), [22, 80, 8000, 8001, 8002])
        self.assertEqual(portopen.parse_ports("ssh,https"), [22, 443])

    def test_parse_ports_rejects_bad_input(self):
        for spec in ("0", "65536", "90-80", "not-a-service", ","):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                portopen.parse_ports(spec)

    def test_split_target(self):
        self.assertEqual(portopen.split_target("example.com"), ("example.com", None))
        self.assertEqual(portopen.split_target("example.com:22,80"), ("example.com", "22,80"))
        self.assertEqual(portopen.split_target("[::1]:443"), ("::1", "443"))
        self.assertEqual(portopen.split_target("[::1]"), ("::1", None))
        self.assertEqual(portopen.split_target("fe80::1"), ("fe80::1", None))
        with self.assertRaises(ValueError):
            portopen.split_target("[::1")

    def test_legacy_host_port_form(self):
        self.assertEqual(portopen.build_targets(["1.1.1.1", "80"]), [("1.1.1.1", 80)])

    def test_trailing_ports_apply_to_hosts_without_ports(self):
        targets = portopen.build_targets(["a", "b:22", "80,443"])
        self.assertEqual(targets, [("a", 80), ("a", 443), ("b", 22)])

    def test_common_ports_are_added(self):
        targets = portopen.build_targets(["a"], ports="12345", common=True)
        self.assertEqual(targets[0], ("a", 12345))
        self.assertIn(("a", 443), targets)

    def test_missing_port_is_an_error(self):
        with self.assertRaises(ValueError):
            portopen.build_targets(["example.com"])

    def test_target_file(self):
        data = "# web\nweb1:80 web2:80  # trailing comment\n\ndb:5432\n"
        with mock.patch("sys.stdin", io.StringIO(data)):
            targets = portopen.build_targets([], file="-")
        self.assertEqual(targets, [("web1", 80), ("web2", 80), ("db", 5432)])


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.listener = Listener(greeting=b"SSH-2.0-Test\r\nextra\x00junk\r\n")
        self.addCleanup(self.listener.close)
        sock, self.closed = closed_port()
        self.addCleanup(sock.close)

    def test_open_and_closed(self):
        results = portopen.scan([("127.0.0.1", self.listener.port), ("127.0.0.1", self.closed)],
                                timeout=1)
        self.assertEqual([r.state for r in results], [OPEN, CLOSED])
        self.assertIsNotNone(results[0].latency_ms)
        self.assertIsNone(results[1].latency_ms)

    def test_banner(self):
        [result] = portopen.scan([("127.0.0.1", self.listener.port)], timeout=1, banner=True)
        self.assertEqual(result.banner, "SSH-2.0-Test extra junk")

    def test_timeout_is_filtered(self):
        with mock.patch.object(socket.socket, "connect", side_effect=socket.timeout):
            [result] = portopen.scan([("127.0.0.1", 9)], timeout=0.1)
        self.assertEqual(result.state, FILTERED)

    def test_other_socket_errors(self):
        error = OSError(113, "No route to host")
        with mock.patch.object(socket.socket, "connect", side_effect=error):
            [result] = portopen.scan([("127.0.0.1", 9)], timeout=0.1)
        self.assertEqual((result.state, result.error), (ERROR, "No route to host"))

    def test_retries_only_unanswered_ports(self):
        with mock.patch.object(socket.socket, "connect", side_effect=socket.timeout) as connect:
            portopen.scan([("127.0.0.1", 9)], timeout=0.1, retries=2)
        self.assertEqual(connect.call_count, 3)
        with mock.patch.object(socket.socket, "connect",
                               side_effect=ConnectionRefusedError) as connect:
            portopen.scan([("127.0.0.1", 9)], timeout=0.1, retries=2)
        self.assertEqual(connect.call_count, 1)

    def test_unresolvable_host(self):
        [result] = portopen.scan([("no-such-host.invalid", 80)], timeout=0.5)
        self.assertEqual(result.state, ERROR)
        self.assertIn("DNS lookup failed", result.error)

    def test_wait_for_port_that_opens_later(self):
        sock, port = closed_port()
        sock.close()

        def open_later():
            time.sleep(0.3)
            server = socket.socket()
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", port))
            server.listen()
            self.addCleanup(server.close)

        threading.Thread(target=open_later).start()
        code, _ = run("127.0.0.1", str(port), "--wait", "5", "--interval", "0.1", "-q")
        self.assertEqual(code, 0)

    def test_wait_gives_up(self):
        code, _ = run(f"127.0.0.1:{self.closed}", "--wait", "0.3", "--interval", "0.1", "-q")
        self.assertEqual(code, 1)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.listener = Listener()
        self.addCleanup(self.listener.close)
        sock, self.closed = closed_port()
        self.addCleanup(sock.close)
        self.open_target = f"127.0.0.1:{self.listener.port}"
        self.closed_target = f"127.0.0.1:{self.closed}"

    def test_exit_status(self):
        self.assertEqual(run(self.open_target, "-q"), (0, ""))
        self.assertEqual(run(self.open_target, self.closed_target, "-q"), (1, ""))

    def test_text_output(self):
        code, out = run("127.0.0.1", str(self.listener.port))
        self.assertEqual(code, 0)
        self.assertIn("open", out)
        self.assertNotIn("checked in", out)  # no summary for a single port

    def test_json_output(self):
        _, out = run(self.open_target, self.closed_target, "-o", "json")
        states = [(r["port"], r["state"]) for r in json.loads(out)]
        self.assertEqual(states, [(self.listener.port, OPEN), (self.closed, CLOSED)])

    def test_csv_open_only(self):
        _, out = run(self.open_target, self.closed_target, "-o", "csv", "--open-only")
        lines = out.strip().splitlines()
        self.assertEqual(lines[0], "host,port,state,address,service,latency_ms,banner,error")
        self.assertEqual(len(lines), 2)
        self.assertIn(f",{self.listener.port},open,", lines[1])

    def test_nagios_ok_and_critical(self):
        code, out = run(self.open_target, "--nagios", "-w", "5", "-c", "10")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("PORT OK - "))
        self.assertIn(f"'{self.open_target}'=", out)
        self.assertIn(";5;10;0;2", out)

        code, out = run(self.open_target, self.closed_target, "--nagios")
        self.assertEqual(code, 2)
        self.assertTrue(out.startswith(f"PORT CRITICAL - {self.closed_target} closed"))

    def test_nagios_slow_response(self):
        results = [Result("h", 1, OPEN, latency_ms=700.0)]
        self.assertEqual(portopen.nagios_report(results, warning=0.5)[0], 1)
        self.assertEqual(portopen.nagios_report(results, warning=0.5, critical=0.6)[0], 2)
        self.assertEqual(portopen.nagios_report(results, warning=1, critical=2)[0], 0)

    def test_usage_errors(self):
        for argv in (["example.com"], ["127.0.0.1", "70000"], [self.open_target, "-w", "1"], []):
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as ctx:
                run(*argv)
            self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
