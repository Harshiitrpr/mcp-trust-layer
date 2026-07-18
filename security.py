import os
import re
import stat
from pathlib import Path
from typing import Match

# Import Windows-specific modules if running on Windows
try:
    import msvcrt
    import win32file
    import win32con
    HAS_WINDOWS_LIBS = True
except ImportError:
    HAS_WINDOWS_LIBS = False

# Maximum input lengths to mitigate ReDoS and buffer exhaustion
MAX_FILENAME_LEN = 255
MAX_KEYWORD_LEN = 100

# Input validation regular expressions
# Restricts input to a predictable filename/path character set and rejects
# shell metacharacters. Absolute-path and directory-containment enforcement
# are performed separately.
SAFE_FILENAME_REGEX = re.compile(r'^[a-zA-Z0-9_\-\./]+$')

# Redaction regular expressions
GOOGLE_API_KEY_REGEX = re.compile(r'AIza[0-9A-Za-z-_]{35}')
JWT_REGEX = re.compile(r'\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+(?:\.[A-Za-z0-9-_=]+)?\b')
AWS_ACCESS_KEY_REGEX = re.compile(r'\bAKIA[0-9A-Z]{16}\b')

# Bearer Token regex
BEARER_REGEX = re.compile(r'(?i)\b(bearer\s+)([A-Za-z0-9-_=\.\+/]{12,})\b')

# Capture key-value style secrets (e.g. password=..., token: ...)
# Captures: Group 1 (opening quote), Group 2 (key), Group 3 (closing quote), Group 4 (separator + optional quotes), Group 5 (secret), Group 6 (trailing quote/separator)
CREDENTIAL_REGEX = re.compile(
    r'(?i)(["\']?)\b([a-zA-Z0-9_-]*(?:password|passwd|secret|api_key|apikey|token|private_key|auth_token))\b(["\']?)(\s*[:=]\s*["\']?)([A-Za-z0-9-_=\.\+/]{12,})([\s"\']?)'
)

def sanitize_filename(filename: str) -> str:
    """
    Sanitizes the input filename to prevent path traversal and shell injection.
    Raises ValueError if validation fails.
    """
    if not filename:
        raise ValueError("Security Exception: Filename cannot be empty.")

    if len(filename) > MAX_FILENAME_LEN:
        raise ValueError(f"Security Exception: Filename exceeds maximum length of {MAX_FILENAME_LEN} characters.")

    # Explicitly reject absolute paths
    if Path(filename).is_absolute():
        raise ValueError("Security Exception: Absolute paths are not allowed.")

    # Explicitly reject nested directories to minimize attack surface
    if Path(filename).name != filename:
        raise ValueError("Security Exception: Nested paths are not allowed.")

    # Prevent basic traversal sequences
    if ".." in filename or "\\" in filename:
        raise ValueError("Security Exception: Path traversal sequence (.. or \\) detected in filename.")

    # Match safe characters only
    if SAFE_FILENAME_REGEX.fullmatch(filename) is None:
        raise ValueError("Security Exception: Invalid characters detected in filename.")

    return filename

def sanitize_keyword(keyword: str) -> str:
    """
    Sanitizes the search keyword to prevent command injection.
    Raises ValueError if validation fails.
    """
    if not keyword:
        raise ValueError("Security Exception: Search keyword cannot be empty.")

    if len(keyword) > MAX_KEYWORD_LEN:
        raise ValueError(f"Security Exception: Search keyword exceeds maximum length of {MAX_KEYWORD_LEN} characters.")

    # Deny-list characters commonly used for command chaining/injection
    invalid_chars = [';', '&', '|', '$', '(', ')', '`', '<', '>', '!', '\n', '\r', '\t']
    if any(char in keyword for char in invalid_chars):
        raise ValueError("Security Exception: Invalid shell characters detected in search payload.")

    return keyword

def get_secure_path(filename: str, base_dir: Path) -> Path:
    """
    Validates the filename and resolves it against base_dir.
    Enforces that the resolved path is strictly within the base directory.
    """
    # 1. Sanitize the user-provided filename string
    clean_filename = sanitize_filename(filename)

    # 2. Resolve both directories to absolute paths
    base_dir_resolved = base_dir.resolve()
    target_path = (base_dir_resolved / clean_filename).resolve()

    # 3. Verify target path is relative to base_dir
    # Prevents escaping base_dir via symlinks or clever path formatting
    if not target_path.is_relative_to(base_dir_resolved):
        raise ValueError("Security Exception: Path traversal attempt blocked.")

    # 4. Do not allow referencing the base directory itself as a file
    if target_path == base_dir_resolved:
        raise ValueError("Security Exception: Access denied to base directory root.")

    return target_path

def open_file_safely(filepath: Path) -> int:
    """
    Opens a file securely, preventing symlink traversal and TOCTOU race conditions.
    Uses os.O_NOFOLLOW on Unix systems. On Windows, uses file stat checks and
    win32file API to verify that the file handle is not a reparse point (symlink/junction).
    """
    if not filepath.exists():
        raise FileNotFoundError(f"Log file '{filepath.name}' does not exist.")

    # Preliminary checks using lstat
    stat_before = os.lstat(filepath)
    if stat.S_ISDIR(stat_before.st_mode):
        raise ValueError(f"Target path is a directory: {filepath.name}")
    if stat.S_ISLNK(stat_before.st_mode):
        raise ValueError("Security Exception: Symlink detected.")

    flags = os.O_RDONLY
    if hasattr(os, 'O_NOFOLLOW'):
        # On Unix, enforce native O_NOFOLLOW to reject symlinks at the OS level
        flags |= os.O_NOFOLLOW
        try:
            return os.open(filepath, flags)
        except OSError as e:
            # ELOOP or other OS errors indicating a symlink/reparse point loop
            import errno
            if e.errno in (errno.ELOOP, errno.EMLINK):
                raise ValueError("Security Exception: Symlink detected.") from e
            raise
    else:
        # Fallback for Windows
        # Open file descriptor first, then inspect it to avoid TOCTOU races
        fd = os.open(filepath, flags)
        try:
            stat_after = os.fstat(fd)
            # Verify file type didn't swap during the open operation
            if stat.S_ISDIR(stat_after.st_mode):
                raise ValueError(f"Target path is a directory: {filepath.name}")
            if stat.S_ISLNK(stat_after.st_mode):
                raise ValueError("Security Exception: Symlink detected.")

            # Check for Windows reparse points (symlinks, mount points, or directory junctions)
            if HAS_WINDOWS_LIBS:
                handle = msvcrt.get_osfhandle(fd)
                file_info = win32file.GetFileInformationByHandle(handle)
                if file_info[0] & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise ValueError("Security Exception: Symlink or reparse point detected.")
        except Exception:
            os.close(fd)
            raise

        return fd

def open_validated_log_file(filepath: Path, max_size: int) -> tuple[int, int]:
    """
    Opens the file safely and verifies size/type on the file descriptor to prevent TOCTOU.
    Returns a tuple of (file_descriptor, file_size_in_bytes).
    """
    fd = open_file_safely(filepath)

    try:
        file_stat = os.fstat(fd)

        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError("Security Exception: Target is not a regular file.")

        if file_stat.st_size > max_size:
            raise ValueError(
                f"Security Exception: Log file size ({file_stat.st_size} bytes) "
                f"exceeds maximum allowed limit of {max_size} bytes."
            )

        return fd, file_stat.st_size
    except Exception:
        os.close(fd)
        raise

def credential_redact_callback(match: Match) -> str:
    """
    Callback for CREDENTIAL_REGEX replacement.
    Redacts only the secret payload while leaving keys and formatting intact.
    """
    open_q = match.group(1)
    key = match.group(2)
    close_q = match.group(3)
    separator = match.group(4)
    suffix = match.group(6)
    return f"{open_q}{key}{close_q}{separator}[REDACTED TOKEN]{suffix}"

def redact_sensitive_data(text: str) -> str:
    """
    Applies regex-based dynamic redaction to remove API keys, JWTs, AWS credentials,
    and inline tokens/passwords from the text.
    """
    if not text:
        return ""

    # Redact Google API keys
    text = GOOGLE_API_KEY_REGEX.sub("[REDACTED API KEY]", text)

    # Redact AWS Access Key IDs
    text = AWS_ACCESS_KEY_REGEX.sub("[REDACTED AWS KEY]", text)

    # Redact JWTs
    text = JWT_REGEX.sub("[REDACTED JWT]", text)

    # Redact Bearer tokens
    text = BEARER_REGEX.sub(r"\1[REDACTED TOKEN]", text)

    # Redact key-value credentials (inline passwords/tokens)
    text = CREDENTIAL_REGEX.sub(credential_redact_callback, text)

    return text
