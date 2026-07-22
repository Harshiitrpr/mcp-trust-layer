# Secure File & Log Analyzer MCP Server

A production-grade, security-hardened Model Context Protocol (MCP) server built with Python and FastMCP. This server exposes a curated catalog of log analysis tools to AI agents while implementing strict input validation, OS-level symlink/TOCTOU mitigation, streaming resource protection, and dynamic response redaction.

---

## 🛠️ Exposed MCP Tools

1. **`list_log_files`**  
   Lists the regular files in the configured safe directory (defaults to `./mock_logs/`), sorted alphabetically.
   
2. **`view_log_summary`**  
   Reads a requested log file and returns its size, line count, and a brief preview.
   
3. **`search_error_patterns`**  
   Streams and searches a given log file for matching keywords (e.g., `"CRITICAL"`, `"ERROR"`), returning matching lines with line numbers.

---

## 🔒 Security Posture & Threat Model

This codebase relies on **defense-in-depth**. For a complete analysis of assets and attackers, see [THREAT_MODEL.md](THREAT_MODEL.md).

| Threat / Attack Vector | Mitigation Strategy | Implementation Details |
| :--- | :--- | :--- |
| **Path Traversal** | Blocks access to system files (`/etc/passwd`). | 1. Input allowlist (`^[a-zA-Z0-9_\-\./]+$`).<br>2. Resolves path and verifies `Path.is_relative_to()`. |
| **Symlink / TOCTOU** | Prevents race condition swapping. | 1. Opens files using `os.O_NOFOLLOW` on Unix.<br>2. On Windows, handle-based validation. |
| **Shell Injection** | Blocks OS command chaining. | 1. Reads files natively in Python.<br>2. Sanitizes keywords against shell metacharacters. |
| **Data Leakage** | Prevents token exfiltration. | 1. Real-time regex redaction engine.<br>2. Masks API keys, JWTs, and AWS credentials. |
| **Resource Exhaustion** | Prevents DoS and OOM crashes. | 1. Line-by-line file streaming.<br>2. Configuration limits on file size and search payload. |

---

## ⚙️ Configuration

The server is configured using environment variables. If not provided, secure defaults are applied:

| Environment Variable | Description | Default Value |
| :--- | :--- | :--- |
| `LOG_ANALYZER_BASE_DIR` | The absolute or relative path to the safe logs folder. | `./mock_logs` |
| `LOG_ANALYZER_MAX_FILE_SIZE` | Maximum file size (in bytes) that the server is allowed to process. | `52428800` (50 MB) |
| `LOG_ANALYZER_MAX_PREVIEW_LINES` | Number of lines returned in the log preview. | `10` |
| `LOG_ANALYZER_MAX_SEARCH_RESULTS` | Maximum number of matching lines returned in a search. | `500` |
| `LOG_ANALYZER_MAX_SEARCH_CHARS` | Maximum character length of the search result response payload. | `100000` (100,000 characters) |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or higher.
- On some systems, use `python3` and `pip3` instead of `python` and `pip`.

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
      "command": "C:\\absolute\\path\\to\\.venv\\Scripts\\python.exe",
      "args": [
        "C:\\absolute\\path\\to\\mcp-trust-layer\\server.py"
      ],
      "env": {
        "LOG_ANALYZER_BASE_DIR": "C:\\absolute\\path\\to\\mcp-trust-layer\\mock_logs",
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
npx -y @modelcontextprotocol/inspector C:\absolute\path\to\.venv\Scripts\python.exe C:\absolute\path\to\mcp-trust-layer\server.py
```

Open the URL output in your terminal to interactively call the tools and test validations.
