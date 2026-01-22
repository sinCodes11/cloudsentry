"""Configuration management for CloudSentry."""

import os
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass, field

import yaml
from dotenv import load_dotenv


load_dotenv()


@dataclass
class OCIConfig:
    config_file: str = "~/.oci/config"
    profile: str = "DEFAULT"
    compartments: List[str] = field(default_factory=lambda: ["ALL"])


@dataclass
class DatabaseConfig:
    host: str = "localhost"
    port: int = 5432
    name: str = "cloudsentry"
    user: str = "cloudsentry"
    password: str = ""

    @property
    def connection_string(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


@dataclass
class SlackConfig:
    enabled: bool = False
    webhook_url: str = ""
    min_severity: str = "HIGH"


@dataclass
class EmailConfig:
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    to: str = ""


@dataclass
class AlertsConfig:
    slack: SlackConfig = field(default_factory=SlackConfig)
    email: EmailConfig = field(default_factory=EmailConfig)


@dataclass
class ScanningConfig:
    schedule: str = "0 */6 * * *"
    parallel_workers: int = 5


@dataclass
class RemediationConfig:
    enabled: bool = False
    auto_fix_severity: List[str] = field(default_factory=list)


@dataclass
class Config:
    oci: OCIConfig = field(default_factory=OCIConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    scanning: ScanningConfig = field(default_factory=ScanningConfig)
    remediation: RemediationConfig = field(default_factory=RemediationConfig)


def _expand_env_vars(value: str) -> str:
    """Expand environment variables in string values."""
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        env_var = value[2:-1]
        return os.getenv(env_var, "")
    return value


def _process_dict(d: dict) -> dict:
    """Recursively process dictionary to expand env vars."""
    result = {}
    for key, value in d.items():
        if isinstance(value, dict):
            result[key] = _process_dict(value)
        elif isinstance(value, str):
            result[key] = _expand_env_vars(value)
        else:
            result[key] = value
    return result


def load_config(config_path: Optional[str] = None) -> Config:
    """Load configuration from YAML file."""
    if config_path is None:
        config_path = os.getenv("CLOUDSENTRY_CONFIG", "config.yaml")

    config_file = Path(config_path)

    if not config_file.exists():
        return Config()

    with open(config_file, "r") as f:
        raw_config = yaml.safe_load(f) or {}

    raw_config = _process_dict(raw_config)

    oci_cfg = raw_config.get("oci", {})
    db_cfg = raw_config.get("database", {})
    alerts_cfg = raw_config.get("alerts", {})
    scanning_cfg = raw_config.get("scanning", {})
    remediation_cfg = raw_config.get("remediation", {})

    slack_cfg = alerts_cfg.get("slack", {})
    email_cfg = alerts_cfg.get("email", {})

    return Config(
        oci=OCIConfig(
            config_file=oci_cfg.get("config_file", "~/.oci/config"),
            profile=oci_cfg.get("profile", "DEFAULT"),
            compartments=oci_cfg.get("compartments", ["ALL"]),
        ),
        database=DatabaseConfig(
            host=db_cfg.get("host", "localhost"),
            port=db_cfg.get("port", 5432),
            name=db_cfg.get("name", "cloudsentry"),
            user=db_cfg.get("user", "cloudsentry"),
            password=db_cfg.get("password", ""),
        ),
        alerts=AlertsConfig(
            slack=SlackConfig(
                enabled=slack_cfg.get("enabled", False),
                webhook_url=slack_cfg.get("webhook_url", ""),
                min_severity=slack_cfg.get("min_severity", "HIGH"),
            ),
            email=EmailConfig(
                enabled=email_cfg.get("enabled", False),
                smtp_host=email_cfg.get("smtp_host", ""),
                smtp_port=email_cfg.get("smtp_port", 587),
                username=email_cfg.get("username", ""),
                password=email_cfg.get("password", ""),
                to=email_cfg.get("to", ""),
            ),
        ),
        scanning=ScanningConfig(
            schedule=scanning_cfg.get("schedule", "0 */6 * * *"),
            parallel_workers=scanning_cfg.get("parallel_workers", 5),
        ),
        remediation=RemediationConfig(
            enabled=remediation_cfg.get("enabled", False),
            auto_fix_severity=remediation_cfg.get("auto_fix_severity", []),
        ),
    )
