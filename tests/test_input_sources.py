import io
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from mcp_lint.cli import main
from mcp_lint.loaders import LoadError, load_stdin, load_url

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def http_export():
    body = (EXAMPLES / "tools_export.json").read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path in {"/redirect", "/ftp"}:
                self.send_response(302)
                self.send_header("Location", "/tools" if self.path == "/redirect" else "ftp://127.0.0.1/tools")
                self.end_headers()
                return
            if self.path == "/error":
                self.send_error(404)
                return
            if self.path == "/slow":
                time.sleep(0.15)
            self.send_response(200)
            # No Content-Length: the reader must enforce its cap on actual bytes.
            self.end_headers()
            payload = {
                "/invalid": b"not json",
                "/encoding": b"\xff",
                "/large": b" " * (5 * 1024 * 1024 + 1),
                "/config": (EXAMPLES / "client_config.json").read_bytes(),
            }.get(self.path, body)
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass  # Expected when the bounded or timed-out client closes early.

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_stdin_matches_file_findings(monkeypatch, capsys):
    source = EXAMPLES / "tools_export.json"
    file_code = main([str(source), "--format", "json"])
    expected = json.loads(capsys.readouterr().out)
    monkeypatch.setattr("sys.stdin", io.StringIO(source.read_text(encoding="utf-8")))
    assert main(["-", "--format", "json"]) == file_code
    actual = json.loads(capsys.readouterr().out)
    for finding in actual["findings"]:
        assert finding["tool"].startswith("<stdin>:")
        finding["tool"] = finding["tool"].replace("<stdin>:", "<inline>:", 1)
    assert actual == expected


def test_stdin_client_config_keeps_server_names():
    tools = load_stdin(io.StringIO('{"mcpServers":{"local":{"command":"test"}}}'))
    assert tools[0].server == "local"


def test_stdin_invalid_json_exits_two(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    assert main(["-"]) == 2
    assert "<stdin> is not valid JSON" in capsys.readouterr().err


def test_stdin_read_error():
    # A decoding failure is reported as a load error rather than a traceback.
    class Unreadable:
        def read(self):
            raise UnicodeError("bad encoding")
    with pytest.raises(LoadError, match="cannot read <stdin>"):
        load_stdin(Unreadable())


def test_duplicate_stdin_rejected_before_read(monkeypatch, capsys):
    stream = io.StringIO("[]")
    monkeypatch.setattr("sys.stdin", stream)
    assert main(["-", "-"]) == 2
    assert stream.tell() == 0
    assert "only be read once" in capsys.readouterr().err


def test_url_cli_matches_file_findings(http_export, capsys):
    file_code = main([str(EXAMPLES / "tools_export.json"), "--format", "json"])
    expected = json.loads(capsys.readouterr().out)
    url = http_export + "/tools"
    assert main(["--url", url, "--format", "json"]) == file_code
    actual = json.loads(capsys.readouterr().out)
    for finding in actual["findings"]:
        assert finding["tool"].startswith(url + ":")
        finding["tool"] = finding["tool"].replace(url + ":", "<inline>:", 1)
    assert actual == expected


def test_url_client_config(http_export):
    assert all(tool.name == "<launch>" for tool in load_url(http_export + "/config"))


def test_url_can_be_combined_with_paths_and_stdin(http_export, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("[]"))
    assert main([str(EXAMPLES / "clean_export.json"), "-", "--url", http_export + "/tools",
                 "--url", http_export + "/tools", "--format", "json"]) == 1
    result = json.loads(capsys.readouterr().out)
    clean = json.loads((EXAMPLES / "clean_export.json").read_text())
    assert result["tools_scanned"] == len(clean["tools"]) + 6


@pytest.mark.parametrize("url", ["file:///tmp/tools.json", "ftp://localhost/tools", "data:,[]",
                                 "https://", "http://[broken", "http://localhost:bad/tools"])
def test_reject_non_http_or_malformed_urls(url, capsys):
    with pytest.raises(LoadError, match="invalid URL"):
        load_url(url)
    assert main(["--url", url]) == 2
    assert "invalid URL" in capsys.readouterr().err


@pytest.mark.parametrize("path", ["/invalid", "/encoding", "/error", "/ftp", "/large"])
def test_url_rejections_are_cli_load_errors(http_export, path, capsys):
    assert main(["--url", http_export + path]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "mcp-lint:" in captured.err


def test_url_size_boundary_and_redirect(http_export):
    size = (EXAMPLES / "tools_export.json").stat().st_size
    assert len(load_url(http_export + "/redirect", max_bytes=size)) == 3
    with pytest.raises(LoadError, match="exceeds"):
        load_url(http_export + "/tools", max_bytes=size - 1)


def test_url_timeout(http_export):
    with pytest.raises(LoadError, match="cannot fetch URL"):
        load_url(http_export + "/slow", timeout=0.02)
