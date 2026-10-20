from pathlib import Path

import pytest

from vigil.agents.registry import build_registry
from vigil.core.settings import Settings


@pytest.fixture
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def registry(tmp_path: Path, project_root: Path):
    settings = Settings(
        data_dir=tmp_path / "data", config_dir=tmp_path / "config", connector_mode="mock",
        fixture_dir=project_root / "fixtures", analysis_dir=project_root / "fixtures" / "safe_samples",
        api_token="test-token",
    )
    settings.prepare()
    return build_registry(settings=settings)

