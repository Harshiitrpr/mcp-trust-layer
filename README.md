# Secure File & Log Analyzer MCP Server

A production-grade, highly secure Model Context Protocol (MCP) server built with Python and FastMCP. This server exposes a curated catalog of log analysis tools to AI agents while implementing strict input validation, OS-level symlink/TOCTOU mitigation, streaming resource protection, and dynamic response redaction.

---

## 🛠️ Exposed MCP Tools

1. **`list_log_files`**  
   Lists the regular files in the configured safe directory (defaults to `./mock_logs/`), sorted alphabetically.
   
2. **`view_log_summary`**  
   Reads a requested log file and returns its size, line count, and a brief preview.
   
3. **`search_error_patterns`**  
   Streams and searches a given log file for matching keywords (e.g., `"CRITICAL"`, `"ERROR"`), returning matching lines with line numbers.

---

## 🔒 Security Posture & Threat Model Mitigations

This codebase is designed using **defense-in-depth** principles to ensure that AI agents cannot exploit the exposed tools to compromise the host system.

| Threat / Attack Vector | Risk | Mitigation Strategy | Implementation Details |
| :--- | :--- | :--- | :--- |
| **Path Traversal** | High | Prevents accessing system files (e.g., `/etc/passwd`) via `../` or absolute paths. | 1. Input sanitization rejects `..` and backslashes.<br>2. Restricts filenames to `^[a-zA-Z0-9_\-\./]+$`.<br>3. Enforces bounds checking with `Path.is_relative_to()`. |
| **Symlink / TOCTOU Swapping** | High | Prevents race conditions where a safe file is replaced with a symlink to a sensitive file between check and read. | 1. Opens files natively using `os.O_NOFOLLOW` on Unix.<br>2. On Windows, opens the file descriptor first, checks `os.fstat`, and verifies the file handle is not a reparse point using `win32file` APIs before reading. |
| **Shell Injection** | High | Prevents agents from executing chained OS commands (e.g., passing `file.log; rm -rf /`). | 1. The server reads files natively in Python (no subprocesses or shell calls).<br>2. String payloads (keywords/filenames) are sanitised against command chaining characters: `;`, `&`, `\|`, `$`, `(`, `)`, `` ` ``, `<`, `>`, `!`, `\n`, `\r`, `\t`. |
| **Credential / Data Leakage** | Medium | Prevents hardcoded API keys, JWTs, AWS credentials, or inline passwords from being returned to the LLM. | 1. Real-time, line-by-line redaction engine using compiled regex scanners.<br>2. Redacts Google API keys, JWTs, AWS Access Key IDs, Bearer tokens, and key-value credentials (e.g., `password=...`, `token: ...`). |
| **Denial of Service (DoS)** | Medium | Prevents memory exhaustion or LLM client crashes when attempting to read large files or returning millions of matches. | 1. File streaming pipeline reads files in small chunks/line-by-line (never loading entire files into memory).<br>2. Rejects files exceeding `MAX_FILE_SIZE_BYTES` (default: 50MB).<br>3. Truncates tool outputs at `MAX_SEARCH_RESULTS` (default: 500 lines) or `MAX_SEARCH_PAYLOAD_CHARS` (default: 100KB) and appends a warning. |

---

## ⚙️ Configuration

The server is configured using environment variables. If not provided, secure defaults are applied:

| Environment Variable | Description | Default Value |
| :--- | :--- | :--- |
| `LOG_ANALYZER_BASE_DIR` | The absolute or relative path to the safe logs folder. | `./mock_logs` |
| `LOG_ANALYZER_MAX_FILE_SIZE` | Maximum file size (in bytes) that the server is allowed to process. | `52428800` (50 MB) |
| `LOG_ANALYZER_MAX_PREVIEW_LINES` | Number of lines returned in the log preview. | `10` |
| `LOG_ANALYZER_MAX_SEARCH_RESULTS` | Maximum number of matching lines returned in a search. | `500` |
| `LOG_ANALYZER_MAX_SEARCH_CHARS` | Maximum character length of the search result response payload. | `100000` (100 KB) |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or higher.
- A virtual environment is highly recommended.

### Installation

1. Clone the repository and navigate to the root directory.
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   # On Windows (PowerShell):
   .\.venv\Scripts\Activate.ps1
   # On Unix/macOS:
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running Tests

Run the comprehensive unit test suite to verify security guards and tools functionality:
```bash
python -m unittest test_server.py
```

---

## 🔌 Connecting to MCP Clients

### 1. Claude Desktop

To add this server to Claude Desktop, edit your `claude_desktop_config.json` (located at `%APPDATA%\Claude\claude_desktop_config.json` on Windows or `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS) and add the server definition:

```json
{
  "mcpServers": {
    "secure-log-analyzer": {
      "command": "C:\\Users\\harsh\\Desktop\\projects\\MCP\\.venv\\Scripts\\python.exe",
      "args": [
        "C:\\Users\\harsh\\Desktop\\projects\\MCP\\server.py"
      ],
      "env": {
        "LOG_ANALYZER_BASE_DIR": "C:\\Users\\harsh\\Desktop\\projects\\MCP\\mock_logs",
        "LOG_ANALYZER_MAX_FILE_SIZE": "52428800"
      }
    }
  }
}
```

> [!NOTE]
> Make sure to adjust the absolute paths to the python executable and the `server.py` file to match your local installation.

### 2. MCP Inspector (Debugging Tool)

You can run and inspect the server using the MCP Inspector tool:

```bash
npx -y @modelcontextprotocol/inspector C:\Users\harsh\Desktop\projects\MCP\.venv\Scripts\python.exe C:\Users\harsh\Desktop\projects\MCP\server.py
```

Open the URL output in your terminal to interactively call the tools and test validations.
