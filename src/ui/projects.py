"""Named projects: each project is exactly one ``.env`` file.

The default project is ``.env`` in the per-user projects directory, and every other project is ``<name>.env`` in the
same directory. A ``.env`` discovered from the launch directory, or chosen explicitly, is the ``local`` project.
"""

from __future__ import annotations

import errno
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ui.config import discover_env, render_new_env
from utils.dotenv import ENV_FILE_VARIABLE

ProjectKind = Literal["default", "named", "local"]

PROJECTS_DIR_VARIABLE = "IMAP_TOOLS_PROJECTS_DIR"
DEFAULT_PROJECT = "default"
LOCAL_PROJECT = "local"
ACTIVE_PROJECT_FILE = ".active-project"
MAX_NAME_LENGTH = 60

_INVALID_CHARACTERS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul", *(f"com{index}" for index in range(1, 10)), *(f"lpt{index}" for index in range(1, 10))}
)


@dataclass(frozen=True)
class Project:
    """One selectable configuration and the file that stores it."""

    name: str
    path: Path
    kind: ProjectKind

    @property
    def managed(self) -> bool:
        """Return whether the project can be renamed or deleted."""
        return self.kind == "named"


def default_projects_dir() -> Path:
    """Return the per-user projects directory, honoring ``IMAP_TOOLS_PROJECTS_DIR``."""
    configured = os.environ.get(PROJECTS_DIR_VARIABLE, "")
    return Path(configured).expanduser() if configured else Path.home() / ".imap-migration-tools"


def validate_name(name: str) -> str:
    """Return a normalized project name, or raise ``ValueError`` with a user-facing reason."""
    normalized = name.strip()
    if not normalized:
        raise ValueError("Project name is required")
    if len(normalized) > MAX_NAME_LENGTH:
        raise ValueError(f"Project name must be {MAX_NAME_LENGTH} characters or fewer")
    if _INVALID_CHARACTERS.search(normalized):
        raise ValueError('Project name cannot contain control characters or any of < > : " / \\ | ? *')
    if normalized.startswith(".") or normalized.endswith("."):
        raise ValueError("Project name cannot start or end with a period")
    folded = normalized.casefold()
    if folded in {DEFAULT_PROJECT, LOCAL_PROJECT}:
        raise ValueError(f'"{normalized}" is reserved')
    if folded.split(".")[0] in _WINDOWS_RESERVED:
        raise ValueError(f'"{normalized}" is reserved by Windows')
    return normalized


class ProjectStore:
    """List, create, rename, delete, and remember projects shared by every desktop frontend."""

    def __init__(self, root: Path | None = None, local_env: Path | None = None) -> None:
        self.root = Path(root or default_projects_dir())
        self.default_path = self.root / ".env"
        self.local_env = local_env

    def ensure_root(self) -> None:
        """Create the owner-only projects directory."""
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            self.root.chmod(stat.S_IRWXU)
        except OSError:
            pass

    def default_project(self) -> Project:
        return Project(DEFAULT_PROJECT, self.default_path, "default")

    def local_project(self) -> Project | None:
        """Return the local project unless its file is the default or a named project."""
        if self.local_env is None or self._project_for_path(Path(self.local_env)) is not None:
            return None
        return Project(LOCAL_PROJECT, Path(self.local_env), "local")

    def named_projects(self) -> list[Project]:
        try:
            entries = [entry for entry in self.root.glob("*.env") if entry.name != ".env" and entry.is_file()]
        except OSError:
            return []
        return sorted(
            (Project(entry.stem, entry, "named") for entry in entries if not entry.stem.startswith(".")),
            key=lambda project: project.name.casefold(),
        )

    def projects(self) -> list[Project]:
        """Return the default project, then the local project, then named projects alphabetically."""
        local = self.local_project()
        return [self.default_project(), *([local] if local else []), *self.named_projects()]

    def find(self, name: str) -> Project | None:
        folded = name.strip().casefold()
        return next((project for project in self.projects() if project.name.casefold() == folded), None)

    def _project_for_path(self, path: Path) -> Project | None:
        resolved = _resolve(path)
        if resolved == _resolve(self.default_path):
            return self.default_project()
        return next((project for project in self.named_projects() if _resolve(project.path) == resolved), None)

    def _check_available(self, name: str, ignore: Project | None = None) -> None:
        folded = name.casefold()
        for project in self.named_projects():
            if project.name.casefold() == folded and project != ignore:
                raise ValueError(f"A project named {project.name} already exists")

    def create(self, name: str) -> Project:
        """Create a new project file with default values, never replacing an existing file."""
        normalized = validate_name(name)
        self._check_available(normalized)
        self.ensure_root()
        path = self.root / f"{normalized}.env"
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
        except FileExistsError:
            raise ValueError(f"A project named {normalized} already exists") from None
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(render_new_env({}))
        return Project(normalized, path, "named")

    def rename(self, project: Project, name: str) -> Project:
        """Move a named project's file to its new name without overwriting another project."""
        if not project.managed:
            raise ValueError(f"The {project.name} project cannot be renamed")
        normalized = validate_name(name)
        if normalized == project.name:
            return project
        self._check_available(normalized, ignore=project)
        target = self.root / f"{normalized}.env"
        if not project.path.is_file():
            raise ValueError(f"The {project.name} project file no longer exists")
        _move_without_replacing(project.path, target, case_only=normalized.casefold() == project.name.casefold())
        renamed = Project(normalized, target, "named")
        if self.remembered() == project.name:
            self.remember(renamed)
        return renamed

    def delete(self, project: Project) -> None:
        """Delete a named project's file."""
        if not project.managed:
            raise ValueError(f"The {project.name} project cannot be deleted")
        try:
            project.path.unlink()
        except FileNotFoundError:
            pass
        if self.remembered() == project.name:
            self.remember(self.default_project())

    def remembered(self) -> str:
        try:
            return (self.root / ACTIVE_PROJECT_FILE).read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    def remember(self, project: Project) -> None:
        """Record the last selected project for the next launch of either frontend."""
        try:
            self.ensure_root()
            (self.root / ACTIVE_PROJECT_FILE).write_text(f"{project.name}\n", encoding="utf-8")
        except OSError:
            pass

    def initial(self, env_path: Path | None = None, project_name: str | None = None) -> Project:
        """Choose the project to open: explicit file, explicit name, remembered, local, then default."""
        if env_path is not None:
            path = Path(env_path).expanduser()
            return self._project_for_path(path) or Project(LOCAL_PROJECT, path, "local")
        if project_name:
            project = self.find(project_name)
            if project is None:
                raise ValueError(f"Project not found: {project_name}")
            return project
        remembered = self.remembered()
        if remembered:
            project = self.find(remembered)
            if project is not None:
                return project
        return self.local_project() or self.default_project()


def _resolve(path: Path) -> Path:
    try:
        return path.expanduser().resolve()
    except OSError:
        return path.expanduser().absolute()


def _move_without_replacing(source: Path, target: Path, case_only: bool, windows: bool = os.name == "nt") -> None:
    """Rename atomically, failing instead of replacing a file created concurrently."""
    if case_only or windows:
        if not case_only and target.exists():
            raise ValueError(f"A project named {target.stem} already exists")
        os.rename(source, target)
        return
    try:
        os.link(source, target)
    except FileExistsError:
        raise ValueError(f"A project named {target.stem} already exists") from None
    except OSError as exc:
        if exc.errno not in {errno.EPERM, errno.EXDEV, errno.ENOTSUP, errno.EOPNOTSUPP}:
            raise
        if target.exists():
            raise ValueError(f"A project named {target.stem} already exists") from None
        os.rename(source, target)
        return
    source.unlink()


def explicit_env(argument: Path | None = None) -> Path | None:
    """Return the ``--env`` argument, else ``IMAP_TOOLS_ENV_FILE``, else nothing."""
    if argument is not None:
        return Path(argument).expanduser()
    configured = os.environ.get(ENV_FILE_VARIABLE, "")
    return Path(configured).expanduser() if configured else None


def local_env(explicit: Path | None = None) -> Path | None:
    """Return the explicit local ``.env`` path, or the discovered one when it exists."""
    if explicit is not None:
        return explicit
    discovered = discover_env()
    return discovered if discovered.is_file() else None


def display_path(path: Path) -> str:
    """Abbreviate the home directory so file locations fit narrow panels."""
    home = str(Path.home())
    location = str(path)
    return "~" + location[len(home) :] if location.startswith(home + os.sep) else location


def run_environment(project: Project) -> dict[str, str]:
    """Pin a subprocess to exactly the active project's file."""
    return {ENV_FILE_VARIABLE: str(_resolve(project.path))}
