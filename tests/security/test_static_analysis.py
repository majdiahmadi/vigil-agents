from pathlib import Path

import pytest

from vigil.integrations.file_analysis.static import StaticFileAnalyzer


def test_static_analysis_is_bounded_and_never_executes(tmp_path: Path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    sample = allowed / "sample.bin"
    sample.write_bytes(b"MZ harmless fixture")
    result = StaticFileAnalyzer(allowed, max_bytes=100).analyze("sample.bin")
    assert result["magic"] == "PE executable header"
    assert result["executed"] is False
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"x")
    with pytest.raises(PermissionError):
        StaticFileAnalyzer(allowed).analyze(str(outside))


def test_static_analysis_rejects_large_file(tmp_path: Path):
    (tmp_path / "large.bin").write_bytes(b"x" * 20)
    with pytest.raises(ValueError, match="exceeds"):
        StaticFileAnalyzer(tmp_path, max_bytes=10).analyze("large.bin")

