import logging
import os
import sys
from fastmcp import FastMCP

from config import Config
from security import (
    get_secure_path,
    open_file_safely,
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
    logger.info("list_log_files: Invoked. BASE_DIR='%s'", Config.BASE_DIR)
    
    if not Config.BASE_DIR.exists():
        logger.error("list_log_files: Configured BASE_DIR '%s' does not exist.", Config.BASE_DIR)
        raise FileNotFoundError(f"Safe log directory '{Config.BASE_DIR}' does not exist.")
    
    if not Config.BASE_DIR.is_dir():
        logger.error("list_log_files: Configured BASE_DIR '%s' is not a directory.", Config.BASE_DIR)
        raise ValueError(f"Safe log directory '{Config.BASE_DIR}' is not a directory.")

    try:
        files = []
        for entry in Config.BASE_DIR.iterdir():
            try:
                # Exclude directories and symlinks for security
                if entry.is_file() and not entry.is_symlink():
                    files.append(entry.name)
            except OSError as entry_err:
                logger.warning("list_log_files: Skipping unreadable entry '%s': %s", entry.name, entry_err)
                
        sorted_files = sorted(files)
        logger.info("list_log_files: Found %d safe files.", len(sorted_files))
        return sorted_files
    except OSError as e:
        logger.error("list_log_files: Failed to list directory contents: %s", e)
        raise ValueError(f"Error accessing safe log directory: {e.strerror}") from e

@mcp.tool()
def view_log_summary(filename: str) -> dict:
    """
    Reads a requested log file and returns its size, line count, and a brief preview.
    Protects against Path Traversal, TOCTOU, and out-of-memory DoS.
    """
    logger.info("view_log_summary: Invoked. filename='%s'", filename)
    
    # 1. Path & Symlink validation
    try:
        secure_path = get_secure_path(filename, Config.BASE_DIR)
    except ValueError as val_err:
        logger.warning("view_log_summary: Path validation failed for '%s': %s", filename, val_err)
        raise
        
    # 2. Size Check
    size_bytes = os.path.getsize(secure_path)
    if size_bytes > Config.MAX_FILE_SIZE_BYTES:
        logger.warning(
            "view_log_summary: File '%s' size (%d bytes) exceeds MAX_FILE_SIZE_BYTES limit (%d bytes).",
            filename, size_bytes, Config.MAX_FILE_SIZE_BYTES
        )
        raise ValueError(
            f"Security Exception: Log file size ({size_bytes} bytes) "
            f"exceeds maximum allowed limit of {Config.MAX_FILE_SIZE_BYTES} bytes."
        )

    # 3. Secure File Open and Streaming (to protect memory / count lines)
    line_count = 0
    preview_lines = []
    
    fd = open_file_safely(secure_path)
    file_obj = None
    try:
        # errors='replace' prevents decoding failures from crashing the tool
        file_obj = open(fd, "r", encoding="utf-8", errors="replace")
        for line in file_obj:
            line_count += 1
            if len(preview_lines) < Config.MAX_PREVIEW_LINES:
                # Apply dynamic redaction line-by-line to prevent leakage
                preview_lines.append(redact_sensitive_data(line.rstrip("\r\n")))
    except Exception as e:
        logger.error("view_log_summary: Error processing file '%s': %s", filename, e)
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
        "view_log_summary: Successfully processed '%s'. Size: %d B, Lines: %d",
        filename, size_bytes, line_count
    )
    
    return {
        "filename": filename,
        "size_bytes": size_bytes,
        "line_count": line_count,
        "preview": "\n".join(preview_lines)
    }

@mcp.tool()
def search_error_patterns(filename: str, keyword: str) -> str:
    """
    Searches a given log file for specific keywords, with shell sanitization and output truncation.
    """
    logger.info("search_error_patterns: Invoked. filename='%s', keyword='%s'", filename, keyword)
    
    # 1. Input & Payload Sanitization
    try:
        clean_keyword = sanitize_keyword(keyword)
        secure_path = get_secure_path(filename, Config.BASE_DIR)
    except ValueError as val_err:
        logger.warning("search_error_patterns: Validation failed: %s", val_err)
        raise

    # 2. Size Check
    size_bytes = os.path.getsize(secure_path)
    if size_bytes > Config.MAX_FILE_SIZE_BYTES:
        logger.warning(
            "search_error_patterns: File '%s' size (%d bytes) exceeds limit.",
            filename, size_bytes
        )
        raise ValueError(
            f"Security Exception: Log file size ({size_bytes} bytes) "
            f"exceeds maximum allowed limit of {Config.MAX_FILE_SIZE_BYTES} bytes."
        )

    # 3. Stream and search
    matches = []
    total_matches_found = 0
    payload_chars = 0
    truncated = False

    fd = open_file_safely(secure_path)
    file_obj = None
    try:
        file_obj = open(fd, "r", encoding="utf-8", errors="replace")
        for line_num, line in enumerate(file_obj, 1):
            if clean_keyword in line:
                total_matches_found += 1
                if truncated:
                    continue
                
                # Apply dynamic redaction line-by-line to prevent leakage of credentials
                redacted_line = redact_sensitive_data(line.rstrip("\r\n"))
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
        logger.error("search_error_patterns: Error searching file '%s': %s", filename, e)
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
        logger.info("search_error_patterns: Finished search. No matches found.")
        return f"No matches found for keyword '{clean_keyword}' in '{filename}'."

    result_text = "\n".join(matches)
    if truncated:
        logger.warning(
            "search_error_patterns: Search results truncated. Found %d matches, returned %d.",
            total_matches_found, len(matches)
        )
        result_text += f"\n\n[WARNING: Results truncated. Showing first {len(matches)} of {total_matches_found} total matches found.]"
    else:
        logger.info("search_error_patterns: Finished search. Found %d matches.", len(matches))
        
    return result_text

# 3. CLI Entrypoint
if __name__ == "__main__":
    mcp.run()