from __future__ import annotations

import os
from pathlib import Path

from platformdirs import user_config_path, user_data_path
from pydantic import BaseModel, Field


class Settings(BaseModel):
    data_dir: Path = Field(default_factory=lambda: Path(os.getenv("VIGIL_DATA_DIR", user_data_path("VIGIL", "Majdi"))))
    config_dir: Path = Field(default_factory=lambda: Path(os.getenv("VIGIL_CONFIG_DIR", user_config_path("VIGIL", "Majdi"))))
    connector_mode: str = Field(default_factory=lambda: os.getenv("VIGIL_CONNECTOR_MODE", "mock"))
    api_token: str | None = Field(default_factory=lambda: os.getenv("VIGIL_API_TOKEN"))
    max_tool_calls: int = 6
    max_events: int = 100
    max_file_bytes: int = 5 * 1024 * 1024
    fixture_dir: Path = Field(default_factory=lambda: Path(__file__).resolve().parents[2] / "fixtures")
    analysis_dir: Path = Field(default_factory=lambda: Path(os.getenv("VIGIL_ANALYSIS_DIR", Path(__file__).resolve().parents[2] / "fixtures" / "safe_samples")))

    @property
    def db_path(self) -> Path:
        return self.data_dir / "vigil.db"

    def prepare(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.analysis_dir.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    settings = Settings()
    settings.prepare()
    return settings

