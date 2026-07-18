import os
from pathlib import Path

class Config:
    """
    Centralized configuration for the Secure File & Log Analyzer MCP Server.
    Uses environment variables with secure, sensible defaults.
    """
    # Base directory for logs, defaulting to the local mock_logs directory.
    # Paths are normalized and resolved at startup.
    BASE_DIR: Path = Path(os.environ.get("LOG_ANALYZER_BASE_DIR", "./mock_logs")).resolve()

    # Maximum file size to process (default: 50MB) to prevent Denial of Service (DoS)
    MAX_FILE_SIZE_BYTES: int = int(os.environ.get("LOG_ANALYZER_MAX_FILE_SIZE", 50 * 1024 * 1024))

    # Maximum lines of preview returned by the view_log_summary tool (default: 10 lines)
    MAX_PREVIEW_LINES: int = int(os.environ.get("LOG_ANALYZER_MAX_PREVIEW_LINES", 10))

    # Maximum search results (lines) to return (default: 500 lines)
    MAX_SEARCH_RESULTS: int = int(os.environ.get("LOG_ANALYZER_MAX_SEARCH_RESULTS", 500))

    # Maximum total characters returned in search payload (default: 100,000 chars)
    # to protect LLM context limits and client memory
    MAX_SEARCH_PAYLOAD_CHARS: int = int(os.environ.get("LOG_ANALYZER_MAX_SEARCH_CHARS", 100_000))
