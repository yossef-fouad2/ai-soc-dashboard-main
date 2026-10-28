"""Install fixed public sources only after validating pinned publisher checksums."""

import hashlib
import io
import json
import stat
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

from ingestion import DATA_DIR, IngestionError, file_hash

OPENSSH_URL = "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log"
OPENSSH_PINNED_URL = (
    "https://raw.githubusercontent.com/logpai/loghub/"
    "374038faa4ca122dd7ca0730372c0b78f76f8597/OpenSSH/OpenSSH_2k.log"
)
OPENSSH_SHA256 = "1e4912727fa88245113d41b16a0cd25ceadba7f931e1c406542885b91254264f"
OPENSSH_BYTES = 225216
OPENSSH_PATH = DATA_DIR / "OpenSSH_2k.log"
SANTOS_URL = "https://zenodo.org/api/records/6610489/files/santos_netflows.zip/content"
SANTOS_BYTES = 25726503
SANTOS_MD5 = "e217db1c0307a8966db9e79609789fcb"
SANTOS_FILES = ("tcp_complete.csv", "tcp_nocomplete.csv", "udp_complete.csv")
SANTOS_MAX_FILE_BYTES = 256 * 1024 * 1024
SANTOS_MAX_TOTAL_BYTES = 512 * 1024 * 1024


def ensure_openssh(path=OPENSSH_PATH):
    path = Path(path)
    if path.exists():
        if not path.is_file() or file_hash(path) != OPENSSH_SHA256:
            raise IngestionError("source_changed", "Existing OpenSSH sample differs from the recorded checksum; it has not been overwritten.")
        return path
    if not (DATA_DIR / "Loghub-LICENSE.txt").is_file():
        raise IngestionError("notice_missing", "The Loghub dataset license notice is required before downloading the sample.")
    try:
        request = urllib.request.Request(OPENSSH_PINNED_URL, headers={"User-Agent": "Local-SOC-Research-Prototype/1.0"})
        with urllib.request.urlopen(request, timeout=45) as response:
            content = response.read(OPENSSH_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise IngestionError("source_unavailable", "Could not download the public OpenSSH sample. Retry when internet access is available.") from exc
    if len(content) != OPENSSH_BYTES or hashlib.sha256(content).hexdigest() != OPENSSH_SHA256:
        raise IngestionError("checksum_mismatch", "Downloaded OpenSSH sample does not match the recorded source checksum.")
    path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation protects existing logs even if two import requests race.
    try:
        with path.open("xb") as handle:
            handle.write(content)
    except FileExistsError:
        if file_hash(path) != OPENSSH_SHA256:
            raise IngestionError("source_changed", "OpenSSH sample changed during installation; no overwrite performed.")
    return path


def ensure_santos(directory=DATA_DIR / "experiments" / "santos"):
    """Fetch the preselected test capture explicitly, never on application startup."""
    directory = Path(directory)
    paths = tuple(directory / name for name in SANTOS_FILES)
    if directory.exists():
        try:
            metadata = json.loads((directory / "provenance.json").read_text(encoding="utf-8"))
            valid = (metadata["source_url"] == SANTOS_URL and metadata["archive_md5"] == SANTOS_MD5
                     and metadata["archive_bytes"] == SANTOS_BYTES
                     and set(metadata["files"]) == set(SANTOS_FILES)
                     and all(path.is_file() and not path.is_symlink()
                             and path.stat().st_size == metadata["files"][path.name]["bytes"]
                             and file_hash(path) == metadata["files"][path.name]["sha256"] for path in paths))
        except (OSError, ValueError, KeyError, TypeError):
            valid = False
        if not valid or directory.is_symlink():
            raise IngestionError("source_changed", "Existing Santos install is incomplete or changed; it has not been overwritten.")
        return paths
    try:
        request = urllib.request.Request(SANTOS_URL, headers={"User-Agent": "Local-SOC-Research-Prototype/1.0"})
        with urllib.request.urlopen(request, timeout=120) as response:
            content = response.read(SANTOS_BYTES + 1)
    except OSError as exc:
        raise IngestionError("source_unavailable", "Could not download the pinned Santos test capture.") from exc
    if len(content) != SANTOS_BYTES or hashlib.md5(content, usedforsecurity=False).hexdigest() != SANTOS_MD5:
        raise IngestionError("checksum_mismatch", "Santos archive differs from the pinned publisher checksum.")
    directory.parent.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            selected, total = {}, 0
            for member in archive.infolist():
                original_name = member.orig_filename
                name = PurePosixPath(original_name)
                if (name.is_absolute() or ".." in name.parts or "\\" in original_name or "\0" in original_name
                        or ":" in original_name or stat.S_ISLNK(member.external_attr >> 16)):
                    raise IngestionError("invalid_archive", "Unsafe Santos archive member.")
                total += member.file_size
                if member.file_size > SANTOS_MAX_FILE_BYTES or total > SANTOS_MAX_TOTAL_BYTES:
                    raise IngestionError("size_limit", "Santos archive exceeds the extraction budget.")
                if not member.is_dir() and name.name in SANTOS_FILES:
                    if name.name in selected:
                        raise IngestionError("invalid_archive", "Duplicate Santos CSV member.")
                    selected[name.name] = member
            if set(selected) != set(SANTOS_FILES):
                raise IngestionError("invalid_archive", "Santos archive does not contain all three expected CSVs.")
            with tempfile.TemporaryDirectory(prefix=".santos-", dir=directory.parent) as temporary:
                staging = Path(temporary) / "complete"
                staging.mkdir()
                files = {}
                for name in SANTOS_FILES:
                    path, count = staging / name, 0
                    digest = hashlib.sha256()
                    with archive.open(selected[name]) as source, path.open("xb") as destination:
                        for chunk in iter(lambda: source.read(1024 * 1024), b""):
                            count += len(chunk)
                            if count > SANTOS_MAX_FILE_BYTES:
                                raise IngestionError("size_limit", "Santos CSV exceeds the extraction budget.")
                            digest.update(chunk)
                            destination.write(chunk)
                    files[name] = {"bytes": count, "sha256": digest.hexdigest()}
                provenance = {
                    "source_url": SANTOS_URL, "doi": "10.5281/zenodo.6610489", "license": "CC-BY-4.0",
                    "archive_md5": SANTOS_MD5, "archive_bytes": SANTOS_BYTES, "files": files,
                    "citation": "Soro et al., AIT Netflow Data Set (2022); Landauer et al., Maintainable Log Datasets for Evaluation of Intrusion Detection Systems; Have It Your Way: Generating Customized Log Datasets With a Model-Driven Simulation Testbed.",
                }
                (staging / "provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
                if directory.exists():
                    raise IngestionError("source_changed", "Santos destination appeared during installation; no overwrite performed.")
                staging.rename(directory)
    except (zipfile.BadZipFile, EOFError, RuntimeError) as exc:
        raise IngestionError("invalid_archive", "Santos archive is corrupt or unsupported.") from exc
    return paths


if __name__ == "__main__":
    sample = ensure_openssh()
    print(json.dumps({"file": str(sample), "source_url": OPENSSH_URL, "pinned_url": OPENSSH_PINNED_URL, "sha256": file_hash(sample)}))
