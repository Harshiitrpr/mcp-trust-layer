import logging
import os
import sys
from fastmcp import FastMCP
from typing import TypedDict

from config import Config
from security import (
    get_secure_path,
    open_validated_log_file,
    redact_sensitive_data,
    sanitize_keyword
)

# 1. Setup Stderr Logging
# In MCP servers, stdout is reserved for JSON-RPC communication.
# Directing application logs to stderr ensures they are captured by the MCP host (like Claude Desktop)
# and do not corrupt the communication protocol.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr
)
logger = logging.getLogger("secure_log_analyzer")

# 2. Initialize FastMCP Server
mcp = FastMCP("SecureLogAnalyzer")

@mcp.tool()
def list_log_files() -> list[str]:
    """
    Lists files in the specific, designated safe directory.
    Only returns regular, non-symlinked files.
    """
    logger.info("tool=list_log_files status=invoked BASE_DIR='%s'", Config.BASE_DIR)
    
    if not Config.BASE_DIR.exists():
        logger.error("tool=list_log_files status=error error_type=missing_dir directory=%r", str(Config.BASE_DIR))
        raise RuntimeError("The configured log directory is unavailable.")
    
    if not Config.BASE_DIR.is_dir():
        logger.error("tool=list_log_files status=error error_type=not_a_directory directory=%r", str(Config.BASE_DIR))
        raise RuntimeError("The configured log directory is unavailable.")

    try:
        files = []
        for entry in Config.BASE_DIR.iterdir():
            try:
                # Exclude directories and symlinks for security
                if entry.is_file() and not entry.is_symlink():
                    files.append(entry.name)
            except OSError as entry_err:
                logger.warning("tool=list_log_files status=skip file='%s' reason='%s'", entry.name, entry_err)
                
        sorted_files = sorted(files)
        logger.info("tool=list_log_files status=success count=%d", len(sorted_files))
        return sorted_files
    except OSError as e:
        logger.error("tool=list_log_files status=error error_type=os_error details=%r", e)
        raise RuntimeError("Error accessing safe log directory.") from e

class LogSummary(TypedDict):
    filename: str
    size_bytes: int
    line_count: int
    preview: str
    preview_truncated: bool

@mcp.tool()
def view_log_summary(filename: str) -> LogSummary:
    """
    Reads a requested log file and returns its size, line count, and a brief preview.
    Protects against Path Traversal, TOCTOU, and out-of-memory DoS.
    """
    # 1. Path & Symlink validation
    try:
        secure_path = get_secure_path(filename, Config.BASE_DIR)
    except ValueError as val_err:
        logger.warning("tool=view_log_summary status=error error_type=validation_failed filename=%r details=%r", filename, val_err)
        raise ValueError("The provided filename is invalid.")
        
    logger.info("tool=view_log_summary status=invoked filename=%r", filename)
    
    # 2. Secure File Open and Size Check (to prevent TOCTOU)
    try:
        fd, size_bytes = open_validated_log_file(secure_path, Config.MAX_FILE_SIZE_BYTES)
    except Exception as e:
        logger.warning("tool=view_log_summary status=error error_type=open_failed filename=%r details=%r", filename, e)
        raise ValueError("Failed to open or validate the log file.")
        
    # 3. Secure Streaming (to protect memory / count lines)
    line_count = 0
    preview_lines = []
    preview_truncated = False
    
    file_obj = None
    try:
        # errors='replace' prevents decoding failures from crashing the tool
        file_obj = open(fd, "r", encoding="utf-8", errors="replace")
        for line in file_obj:
            line_count += 1
            if len(preview_lines) < Config.MAX_PREVIEW_LINES:
                # Truncate extremely long lines before regex to avoid memory/ReDoS issues
                clean_line = line.rstrip("\r\n")
                if len(clean_line) > Config.MAX_LINE_CHARS:
                    clean_line = clean_line[:Config.MAX_LINE_CHARS] + "… [LINE TRUNCATED]"
                
                # Apply dynamic redaction line-by-line to prevent leakage
                preview_lines.append(redact_sensitive_data(clean_line))
            elif not preview_truncated:
                preview_truncated = True
    except Exception as e:
        logger.error("tool=view_log_summary status=error error_type=read_failed filename=%r details=%r", filename, e)
        raise
    finally:
        if file_obj:
            file_obj.close()
        else:
            try:
                os.close(fd)
            except OSError:
                pass

    logger.info(
        "tool=view_log_summary status=success filename=%r size_bytes=%d line_count=%d",
        filename, size_bytes, line_count
    )
    
    return {
        "filename": filename,
        "size_bytes": size_bytes,
        "line_count": line_count,
        "preview": "\n".join(preview_lines),
        "preview_truncated": preview_truncated
    }

@mcp.tool()
def search_error_patterns(filename: str, keyword: str) -> str:
    """
    Searches a given log file for specific keywords, with shell sanitization and output truncation.
    Search is literal and case-insensitive.
    """
    # 1. Input & Payload Sanitization
    try:
        clean_keyword = sanitize_keyword(keyword)
        secure_path = get_secure_path(filename, Config.BASE_DIR)
    except ValueError as val_err:
        logger.warning("tool=search_error_patterns status=error error_type=validation_failed details=%r", val_err)
        raise ValueError("Invalid filename or search keyword provided.")

    logger.info("tool=search_error_patterns status=invoked filename=%r keyword=%r", filename, clean_keyword)

    # 2. Secure File Open and Size Check
    try:
        fd, size_bytes = open_validated_log_file(secure_path, Config.MAX_FILE_SIZE_BYTES)
    except Exception as e:
        logger.warning("tool=search_error_patterns status=error error_type=open_failed filename=%r details=%r", filename, e)
        raise ValueError("Failed to open or validate the log file.")

    # 3. Stream and search
    matches = []
    total_matches_found = 0
    payload_chars = 0
    truncated = False
    
    search_term = clean_keyword.casefold()

    file_obj = None
    try:
        file_obj = open(fd, "r", encoding="utf-8", errors="replace")
        for line_num, line in enumerate(file_obj, 1):
            if search_term in line.casefold():
                total_matches_found += 1
                if truncated:
                    continue
                
                # Truncate line length
                clean_line = line.rstrip("\r\n")
                if len(clean_line) > Config.MAX_LINE_CHARS:
                    clean_line = clean_line[:Config.MAX_LINE_CHARS] + "… [LINE TRUNCATED]"
                
                # Apply dynamic redaction line-by-line to prevent leakage of credentials
                redacted_line = redact_sensitive_data(clean_line)
                formatted_line = f"Line {line_num}: {redacted_line}"
                
                # Check limits before adding to matches list
                if len(matches) >= Config.MAX_SEARCH_RESULTS:
                    truncated = True
                    continue
                
                if payload_chars + len(formatted_line) > Config.MAX_SEARCH_PAYLOAD_CHARS:
                    truncated = True
                    continue
                
                matches.append(formatted_line)
                payload_chars += len(formatted_line) + 1 # +1 for newline
    except Exception as e:
        logger.error("tool=search_error_patterns status=error error_type=read_failed filename=%r details=%r", filename, e)
        raise
    finally:
        if file_obj:
            file_obj.close()
        else:
            try:
                os.close(fd)
            except OSError:
                pass

    if not matches:
        logger.info("tool=search_error_patterns status=success matches=0 keyword=%r filename=%r", clean_keyword, filename)
        return f"No matches found for keyword '{clean_keyword}' in '{filename}'."

    result_text = "\n".join(matches)
    if truncated:
        logger.warning(
            "tool=search_error_patterns status=success_truncated total_matches=%d returned_matches=%d",
            total_matches_found, len(matches)
        )
        result_text += f"\n\n[WARNING: Results truncated. Showing first {len(matches)} of {total_matches_found} total matches found.]"
    else:
        logger.info("tool=search_error_patterns status=success total_matches=%d", len(matches))
        
    return result_text

# 3. CLI Entrypoint
if __name__ == "__main__":
    mcp.run()