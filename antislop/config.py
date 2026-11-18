"""
Configuration management, ignore lists, and language mappings for SlopSentinel.
"""

from dataclasses import dataclass, field
from typing import List, Set
import os

DEFAULT_IGNORE_DIRS: Set[str] = {
    ".git", ".svn", ".hg", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".tox", ".venv", "venv", "env", "node_modules", "bower_components",
    "dist", "build", ".next", ".nuxt", "out", "target", ".idea", ".vscode",
    "vendor", ".gemini", "coverage", ".turbo", "bin", "obj"
}

DEFAULT_IGNORE_FILES: Set[str] = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock",
    "tags", ".DS_Store", "Thumbs.db"
}

DEFAULT_IGNORE_EXTENSIONS: Set[str] = {
    ".min.js", ".min.css", ".map", ".lock", ".png", ".jpg", ".jpeg",
    ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".mp4",
    ".webm", ".mp3", ".wav", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".pyo", ".pyd",
    ".db", ".sqlite", ".sqlite3"
}

SUPPORTED_EXTENSIONS = {
    # Python
    ".py": "python",
    ".pyi": "python",
    # JavaScript & TypeScript
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    # Systems & Compiled
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".h": "c_header",
    ".hpp": "cpp_header",
    ".cs": "csharp",
    # Configs & Deployments
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".env": "env",
    ".sh": "shell",
    ".bash": "shell",
    ".ps1": "powershell",
    "dockerfile": "dockerfile"
}


@dataclass
class ScanConfig:
    target_path: str = "."
    ignore_dirs: Set[str] = field(default_factory=lambda: set(DEFAULT_IGNORE_DIRS))
    ignore_files: Set[str] = field(default_factory=lambda: set(DEFAULT_IGNORE_FILES))
    ignore_extensions: Set[str] = field(default_factory=lambda: set(DEFAULT_IGNORE_EXTENSIONS))
    max_file_size_kb: int = 1500  # 1.5 MB limit
    entropy_threshold: float = 4.2
    enable_security: bool = True
    enable_slop: bool = True
    enable_gaps: bool = True
    strict_mode: bool = False
    output_format: str = "console"  # console, json, sarif, html
    output_file: str = ""
    auto_fix: bool = False
    dry_run: bool = False

    def is_file_ignored(self, file_path: str) -> bool:
        norm = os.path.normpath(file_path)
        parts = norm.split(os.sep)

        for part in parts:
            if part in self.ignore_dirs:
                return True

        base_name = os.path.basename(file_path).lower()
        if base_name in self.ignore_files:
            return True

        for ext in self.ignore_extensions:
            if base_name.endswith(ext):
                return True

        return False
