import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

@dataclass(frozen=True)
class AppConfig:
    """
    Centralized configuration for the Secure File & Log Analyzer MCP Server.
    Uses environment variables with secure, sensible defaults.
    """
    # Base directory for logs, defaulting to the local mock_logs directory.
    # Paths are normalized and resolved at startup.
    BASE_DIR: Path = field(default_factory=lambda: Path(os.environ.get("LOG_ANALYZER_BASE_DIR", "./mock_logs")).resolve())

    # Maximum file size to process (default: 50MB) to prevent Denial of Service (DoS)
    MAX_FILE_SIZE_BYTES: int = field(default_factory=lambda: int(os.environ.get("LOG_ANALYZER_MAX_FILE_SIZE", 50 * 1024 * 1024)))

    # Maximum lines of preview returned by the view_log_summary tool (default: 10 lines)
    MAX_PREVIEW_LINES: int = field(default_factory=lambda: int(os.environ.get("LOG_ANALYZER_MAX_PREVIEW_LINES", 10)))

    # Maximum character limit for a single line (default: 16KB) to prevent ReDoS or memory exhaustion on maliciously long lines
    MAX_LINE_CHARS: int = field(default_factory=lambda: int(os.environ.get("LOG_ANALYZER_MAX_LINE_CHARS", 16_384)))

    # Maximum search results (lines) to return (default: 500 lines)
    MAX_SEARCH_RESULTS: int = field(default_factory=lambda: int(os.environ.get("LOG_ANALYZER_MAX_SEARCH_RESULTS", 500)))

    # Maximum total characters returned in search payload (default: 100,000 chars)
    # to protect LLM context limits and client memory
    MAX_SEARCH_PAYLOAD_CHARS: int = field(default_factory=lambda: int(os.environ.get("LOG_ANALYZER_MAX_SEARCH_CHARS", 100_000)))

    def __post_init__(self):
        # Validate positive limits
        if self.MAX_FILE_SIZE_BYTES <= 0:
            raise ValueError("LOG_ANALYZER_MAX_FILE_SIZE must be positive")
        if self.MAX_PREVIEW_LINES <= 0:
            raise ValueError("LOG_ANALYZER_MAX_PREVIEW_LINES must be positive")
        if self.MAX_LINE_CHARS <= 0:
            raise ValueError("LOG_ANALYZER_MAX_LINE_CHARS must be positive")
        if self.MAX_SEARCH_RESULTS <= 0:
            raise ValueError("LOG_ANALYZER_MAX_SEARCH_RESULTS must be positive")
        if self.MAX_SEARCH_PAYLOAD_CHARS <= 0:
            raise ValueError("LOG_ANALYZER_MAX_SEARCH_CHARS must be positive")
            
        # Validate base directory
        if not self.BASE_DIR.exists():
            raise ValueError(f"Startup check failed: BASE_DIR '{self.BASE_DIR}' does not exist.")
        if not self.BASE_DIR.is_dir():
            raise ValueError(f"Startup check failed: BASE_DIR '{self.BASE_DIR}' is not a directory.")
        if not os.access(self.BASE_DIR, os.R_OK):
            raise ValueError(f"Startup check failed: BASE_DIR '{self.BASE_DIR}' is not readable.")
            
        # Check if symlink using lstat
        try:
            stat_info = os.lstat(self.BASE_DIR)
            if stat.S_ISLNK(stat_info.st_mode):
                raise ValueError(f"Startup check failed: BASE_DIR '{self.BASE_DIR}' cannot be a symlink.")
        except OSError as e:
            raise ValueError(f"Startup check failed: Error accessing BASE_DIR '{self.BASE_DIR}': {e}")

Config = AppConfig()
