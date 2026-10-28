"""Bounded installer tests using tiny local fixtures, never the final capture."""

import hashlib
import io
import zipfile

import pytest

import sources
from ingestion import IngestionError


def archive_bytes(names=None):
    handle = io.BytesIO()
    with zipfile.ZipFile(handle, "w") as archive:
        for name in names or ["santos/" + name for name in sources.SANTOS_FILES]:
            member = zipfile.ZipInfo("placeholder")
            member.filename = name
            archive.writestr(member, "controlled,fixture\n1,2\n")
    return handle.getvalue()


def fake_download(monkeypatch, content):
    monkeypatch.setattr(sources, "SANTOS_BYTES", len(content))
    monkeypatch.setattr(sources, "SANTOS_MD5", hashlib.md5(content, usedforsecurity=False).hexdigest())
    calls = []

    def open_url(request, timeout):
        assert request.full_url == sources.SANTOS_URL
        assert timeout == 120
        calls.append(request.full_url)
        return io.BytesIO(content)

    monkeypatch.setattr(sources.urllib.request, "urlopen", open_url)
    return calls


def test_installs_verified_files_with_provenance_and_reuses_unchanged_cache(tmp_path, monkeypatch):
    calls = fake_download(monkeypatch, archive_bytes())
    directory = tmp_path / "capture"
    paths = sources.ensure_santos(directory)
    assert tuple(path.name for path in paths) == sources.SANTOS_FILES
    assert all(path.read_text() == "controlled,fixture\n1,2\n" for path in paths)
    assert (directory / "provenance.json").exists()
    assert sources.ensure_santos(directory) == paths
    assert len(calls) == 1
    paths[0].write_text("user changes")
    with pytest.raises(IngestionError, match="not been overwritten"):
        sources.ensure_santos(directory)
    assert paths[0].read_text() == "user changes"
    assert len(calls) == 1


def test_existing_incomplete_directory_is_never_overwritten(tmp_path, monkeypatch):
    calls = fake_download(monkeypatch, archive_bytes())
    directory = tmp_path / "capture"
    directory.mkdir()
    existing = directory / "tcp_complete.csv"
    existing.write_text("original data")
    with pytest.raises(IngestionError, match="not been overwritten"):
        sources.ensure_santos(directory)
    assert existing.read_text() == "original data" and not calls


def test_bad_checksum_cannot_publish_files(tmp_path, monkeypatch):
    fake_download(monkeypatch, archive_bytes())
    monkeypatch.setattr(sources, "SANTOS_MD5", "0" * 32)
    directory = tmp_path / "capture"
    with pytest.raises(IngestionError, match="checksum"):
        sources.ensure_santos(directory)
    assert not directory.exists()


@pytest.mark.parametrize("extra", ["../escape.csv", "/absolute.csv", "C:/absolute.csv", "folder\\escape.csv", "other/tcp_complete.csv"])
def test_unsafe_or_duplicate_members_cannot_escape_staging(tmp_path, monkeypatch, extra):
    names = ["santos/" + name for name in sources.SANTOS_FILES] + [extra]
    fake_download(monkeypatch, archive_bytes(names))
    directory = tmp_path / "capture"
    with pytest.raises(IngestionError, match="Unsafe|Duplicate"):
        sources.ensure_santos(directory)
    assert not directory.exists()
    assert not (tmp_path / "escape.csv").exists()


def test_size_budget_and_missing_expected_member_fail(tmp_path, monkeypatch):
    fake_download(monkeypatch, archive_bytes())
    monkeypatch.setattr(sources, "SANTOS_MAX_FILE_BYTES", 1)
    with pytest.raises(IngestionError, match="budget"):
        sources.ensure_santos(tmp_path / "large")
    monkeypatch.setattr(sources, "SANTOS_MAX_FILE_BYTES", 1000)
    fake_download(monkeypatch, archive_bytes(["tcp_complete.csv"]))
    with pytest.raises(IngestionError, match="all three"):
        sources.ensure_santos(tmp_path / "missing")
