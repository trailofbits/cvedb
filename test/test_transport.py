from dataclasses import replace
from unittest.mock import patch

import pytest

from cvedb import nvd
from test.feed_fixtures import Response, snapshot

URL = "https://example.test/feed.json.gz"


@pytest.mark.parametrize("progress", [False, True])
def test_download_uses_explicit_timeout_and_bounded_reads(progress: bool) -> None:
    response = Response(b"payload", chunk_size=2)
    with patch("cvedb.nvd.urllib.request.urlopen", return_value=response) as opener:
        assert nvd.download(URL, 7, progress) == b"payload"
    assert opener.call_args.kwargs["timeout"] == 30
    assert response.read_sizes and all(size > 0 for size in response.read_sizes)


@pytest.mark.parametrize("expected", [2, 20])
def test_download_rejects_length_mismatch(expected: int) -> None:
    with patch("cvedb.nvd.urllib.request.urlopen", return_value=Response(b"payload")):
        with pytest.raises(ValueError, match="example.test"):
            nvd.download(URL, expected, False)


def test_download_rejects_oversized_declared_length_before_connecting() -> None:
    with (
        patch.object(nvd, "_MAX_GZIP_BYTES", 4, create=True),
        patch("cvedb.nvd.urllib.request.urlopen") as opener,
    ):
        with pytest.raises(ValueError, match="example.test"):
            nvd.download(URL, 5, False)
    opener.assert_not_called()


def test_download_rejects_unknown_length_growth() -> None:
    response = Response(b"payload", chunk_size=2)
    response.headers.clear()
    with (
        patch.object(nvd, "_MAX_GZIP_BYTES", 4, create=True),
        patch("cvedb.nvd.urllib.request.urlopen", return_value=response),
    ):
        with pytest.raises(ValueError, match="example.test"):
            nvd.download(URL, None, False)


def test_trickling_response_hits_transfer_deadline_without_real_wait() -> None:
    clock = [0.0]

    def advance() -> None:
        clock[0] += 20

    response = Response(b"x" * 100, chunk_size=1, after_read=advance)
    with (
        patch.object(nvd, "monotonic", side_effect=lambda: clock[0], create=True),
        patch("cvedb.nvd.urllib.request.urlopen", return_value=response),
    ):
        with pytest.raises((OSError, ValueError), match="deadline|timed out"):
            nvd.download(URL, None, False)
    assert clock[0] < 1000


@pytest.mark.parametrize("error", [OSError("offline"), TimeoutError("socket timeout")])
def test_transport_errors_include_url_context(error: OSError) -> None:
    with patch("cvedb.nvd.urllib.request.urlopen", side_effect=error):
        with pytest.raises(OSError, match="example.test") as caught:
            nvd.download(URL, show_progress=False)
    assert caught.value.__cause__ is error


def test_synthetic_metadata_remains_valid_for_direct_json_loading() -> None:
    data = nvd.JsonDataSource.load({"CVE_data_timestamp": "2020-01-02T00:00:00Z", "CVE_Items": []})
    assert data.meta.sha256 == b""
    assert list(data) == []


def test_bad_metadata_is_checked_before_unchanged_acceptance() -> None:
    from io import BytesIO
    from cvedb.feed import InMemoryData
    from test.feed_fixtures import LocalJsonFeed, NOW

    value = snapshot()
    bad = replace(value, meta=replace(value.meta, sha256=b"bad"))
    parent = LocalJsonFeed("invalid-meta")
    existing = InMemoryData(NOW, ())
    with patch("cvedb.nvd.urllib.request.urlopen", return_value=BytesIO(bad.metadata())):
        with pytest.raises(ValueError, match="invalid-meta"):
            parent.reload(existing)


def test_http_error_response_is_closed_before_contextual_failure() -> None:
    from io import BytesIO
    from urllib.error import HTTPError
    from email.message import Message

    body = BytesIO(b"unavailable")
    error = HTTPError(URL, 503, "unavailable", Message(), body)
    with patch("cvedb.nvd.urllib.request.urlopen", side_effect=error):
        with pytest.raises(OSError, match="example.test") as caught:
            nvd.download(URL, show_progress=False)
    assert body.closed
    assert caught.value.__cause__ is error


def test_mid_read_protocol_failure_closes_response_and_preserves_cause() -> None:
    from http.client import IncompleteRead

    error = IncompleteRead(b"partial", 10)

    def fail() -> None:
        raise error

    response = Response(b"payload", after_read=fail)
    with patch("cvedb.nvd.urllib.request.urlopen", return_value=response):
        with pytest.raises(OSError, match="example.test") as caught:
            nvd.download(URL, show_progress=False)
    assert response.stream.closed
    assert caught.value.__cause__ is error


@pytest.mark.parametrize("length", ["invalid", "-1", "1000", "3"])
def test_bad_response_length_is_contextual_and_closes_body(length: str) -> None:
    response = Response(b"payload")
    response.headers["Content-Length"] = length
    with (
        patch.object(nvd, "_MAX_GZIP_BYTES", 100, create=True),
        patch("cvedb.nvd.urllib.request.urlopen", return_value=response),
    ):
        with pytest.raises(ValueError, match="example.test"):
            nvd.download(URL, show_progress=False)
    assert response.stream.closed


@pytest.mark.parametrize("value", [None, "text"])
def test_nonbyte_transport_read_fails_and_closes_response(value: object) -> None:
    response = Response(b"payload")
    with (
        patch("cvedb.nvd.urllib.request.urlopen", return_value=response),
        patch.object(response, "read1", return_value=value),
    ):
        with pytest.raises(ValueError, match="example.test.*bytes"):
            nvd.download(URL, show_progress=False)
    assert response.stream.closed


@pytest.mark.parametrize("expected", [-1, 5])
def test_negative_and_overlimit_sizes_fail_before_io(expected: int) -> None:
    with (
        patch.object(nvd, "_MAX_GZIP_BYTES", 4),
        patch("cvedb.nvd.urllib.request.urlopen") as opener,
    ):
        with pytest.raises(ValueError, match="example.test"):
            nvd.download(URL, expected, False)
    opener.assert_not_called()


@pytest.mark.parametrize("expected", [None, 0])
def test_generic_empty_download_is_valid(expected: int | None) -> None:
    response = Response(b"")
    with patch("cvedb.nvd.urllib.request.urlopen", return_value=response):
        assert nvd.download(URL, expected, False) == b""
    assert response.stream.closed


def test_chunked_reads_preserve_data_and_enforce_limits() -> None:
    from hypothesis import given, settings, strategies as st

    @given(body=st.binary(max_size=256), chunk=st.integers(1, 64), limit=st.integers(0, 256))
    @settings(max_examples=75, derandomize=True, deadline=None)
    def verify(body: bytes, chunk: int, limit: int) -> None:
        response = Response(body, chunk_size=chunk)
        response.headers.clear()
        with (
            patch.object(nvd, "_MAX_GZIP_BYTES", limit),
            patch("cvedb.nvd.urllib.request.urlopen", return_value=response),
        ):
            if len(body) > limit:
                with pytest.raises(ValueError, match="example.test"):
                    nvd.download(URL, show_progress=False)
            else:
                assert nvd.download(URL, show_progress=False) == body
        assert response.stream.closed
        assert all(size > 0 for size in response.read_sizes)

    verify()
