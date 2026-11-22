"""Configuration file loading, saving, and workspace initialisation."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

import yaml

from harness.config.schema import HarnessConfig

DEFAULT_CONFIG_REL = Path(".harness") / "config.yaml"


def find_config_path(start: Optional[Path] = None) -> Path:
    """Return the path to `.harness/config.yaml`, searching upwards from `start`."""
    current = (start or Path.cwd()).resolve()
    for parent in [current, *current.parents]:
        candidate = parent / DEFAULT_CONFIG_REL
        if candidate.exists():
            return candidate
    return current / DEFAULT_CONFIG_REL


def default_config(project_name: str = "my-project", asset_code: str = "HARNESS-001") -> HarnessConfig:
    """Create a default validated HarnessConfig for a project."""
    cfg = HarnessConfig()
    cfg.project.name = project_name
    cfg.project.asset_code = asset_code
    return cfg


def load_config(path: Optional[Path] = None) -> HarnessConfig:
    """Load and validate `.harness/config.yaml`. Raises FileNotFoundError if absent."""
    target = path or find_config_path()
    if not target.exists():
        raise FileNotFoundError(
            f"Harness configuration not found at {target}. Run 'harness init' first."
        )
    raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    return HarnessConfig.model_validate(raw)


def save_config(config: HarnessConfig, path: Optional[Path] = None) -> Path:
    """Serialise and write a validated HarnessConfig to YAML."""
    target = path or find_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    # mode="json" converts Enums cleanly to plain strings for YAML output
    data = config.model_dump(mode="json")
    target.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return target


def ensure_local_git(root: Path, base_branch: str = "main", remote_url: Optional[str] = None) -> bool:
    """Initialise a local Git repository if none exists; optionally set origin remote.

    Returns True if a new repository was initialised, False if one already existed.
    """
    if (root / ".git").exists():
        return False

    subprocess.run(
        ["git", "init", "-b", base_branch],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    if remote_url:
        subprocess.run(
            ["git", "remote", "add", "origin", remote_url],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    return True


def init_workspace(
    root: Optional[Path] = None,
    project_name: Optional[str] = None,
    asset_code: str = "HARNESS-001",
    repository_url: Optional[str] = None,
    overwrite: bool = False,
) -> tuple[Path, HarnessConfig, bool]:
    """Initialise `.harness/` config, local SQLite state, audit log, and local Git.

    Returns `(config_path, config, git_initialised)`.
    """
    workspace = (root or Path.cwd()).resolve()
    config_path = workspace / DEFAULT_CONFIG_REL
    if config_path.exists() and not overwrite:
        cfg = load_config(config_path)
    else:
        name = project_name or workspace.name
        cfg = default_config(project_name=name, asset_code=asset_code)
        if repository_url:
            cfg.project.repository_url = repository_url
            cfg.project.local_git_only = False
        save_config(cfg, config_path)

    git_created = ensure_local_git(
        workspace,
        base_branch=cfg.git.base_branch,
        remote_url=None if cfg.project.local_git_only else cfg.project.repository_url,
    )
    return config_path, cfg, git_created
