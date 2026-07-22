import os
import unittest
import tempfile
import dataclasses
from unittest import mock
from pathlib import Path

# Set up test environment variables before importing Config
os.makedirs("./mock_logs", exist_ok=True)
os.environ["LOG_ANALYZER_BASE_DIR"] = "./mock_logs"
os.environ["LOG_ANALYZER_MAX_FILE_SIZE"] = str(50 * 1024 * 1024)  # 50MB default for general tests
os.environ["LOG_ANALYZER_MAX_PREVIEW_LINES"] = "10"
os.environ["LOG_ANALYZER_MAX_SEARCH_RESULTS"] = "500"
os.environ["LOG_ANALYZER_MAX_SEARCH_CHARS"] = "100000"

import config
import server
from security import (
    sanitize_filename,
    sanitize_keyword,
    get_secure_path,
    open_file_safely,
    redact_sensitive_data
)
from server import list_log_files, view_log_summary, search_error_patterns

class TestSecureLogAnalyzer(unittest.TestCase):
    
    def setUp(self):
        # Create a temporary directory for safe file tests
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name).resolve()
        
        # Override BASE_DIR in Config for isolated testing using mock.patch
        new_config = dataclasses.replace(server.Config, BASE_DIR=self.base_path)
        self.config_patcher = mock.patch('server.Config', new_config)
        self.config_patcher.start()
        
    def tearDown(self):
        # Restore original configuration and clean up temp folder
        self.config_patcher.stop()
        self.test_dir.cleanup()

    # ==========================================
    # 1. Configuration Tests
    # ==========================================
    def test_config_loading(self):
        self.assertEqual(server.Config.MAX_FILE_SIZE_BYTES, 50 * 1024 * 1024)
        self.assertEqual(server.Config.MAX_PREVIEW_LINES, 10)
        self.assertEqual(server.Config.MAX_SEARCH_RESULTS, 500)
        self.assertEqual(server.Config.MAX_SEARCH_PAYLOAD_CHARS, 100000)

    def test_config_validation(self):
        with self.assertRaises(ValueError):
            config.AppConfig(MAX_FILE_SIZE_BYTES=-1)
        with self.assertRaises(ValueError):
            config.AppConfig(BASE_DIR=Path("/does/not/exist"))

    # ==========================================
    # 2. Input Sanitization Tests
    # ==========================================
    def test_filename_sanitization_valid(self):
        self.assertEqual(sanitize_filename("api.log"), "api.log")
        self.assertEqual(sanitize_filename("sys.log"), "sys.log")
        self.assertEqual(sanitize_filename("sub_dir-1.2.log"), "sub_dir-1.2.log")

    def test_filename_sanitization_absolute(self):
        with self.assertRaises(ValueError):
            sanitize_filename("/etc/passwd")
        with self.assertRaises(ValueError):
            sanitize_filename("C:\\Windows\\System32")

    def test_filename_sanitization_nested(self):
        with self.assertRaises(ValueError):
            sanitize_filename("logs/api.log")

    def test_filename_sanitization_empty(self):
        with self.assertRaises(ValueError):
            sanitize_filename("")

    def test_filename_sanitization_too_long(self):
        long_name = "a" * 256
        with self.assertRaises(ValueError):
            sanitize_filename(long_name)

    def test_filename_sanitization_traversal(self):
        # Traversal sequences
        with self.assertRaises(ValueError):
            sanitize_filename("../etc/passwd")
        with self.assertRaises(ValueError):
            sanitize_filename("..\\etc\\passwd")
        with self.assertRaises(ValueError):
            sanitize_filename("logs/../../etc/passwd")

    def test_filename_sanitization_unsafe_chars(self):
        # Shell injection characters
        unsafe_filenames = [
            "api.log; rm -rf /",
            "api.log&&id",
            "api.log|whoami",
            "$(whoami).log",
            "api.log`id`",
            "api:log"  # Colon (Windows drive letter potential)
        ]
        for name in unsafe_filenames:
            with self.assertRaises(ValueError, msg=f"Failed to reject unsafe filename: {name}"):
                sanitize_filename(name)

    def test_keyword_sanitization_valid(self):
        self.assertEqual(sanitize_keyword("ERROR"), "ERROR")
        self.assertEqual(sanitize_keyword("User login: success"), "User login: success")

    def test_keyword_sanitization_empty(self):
        with self.assertRaises(ValueError):
            sanitize_keyword("")

    def test_keyword_sanitization_too_long(self):
        long_keyword = "a" * 101
        with self.assertRaises(ValueError):
            sanitize_keyword(long_keyword)

    def test_keyword_sanitization_unsafe(self):
        unsafe_keywords = [
            "ERROR; rm -rf",
            "CRITICAL && cat /etc/passwd",
            "INFO | nc -l 4444",
            "$(id)",
            "`id`",
            "ERROR\nDEBUG"
        ]
        for kw in unsafe_keywords:
            with self.assertRaises(ValueError, msg=f"Failed to reject unsafe keyword: {kw}"):
                sanitize_keyword(kw)

    # ==========================================
    # 3. Path Validation Tests
    # ==========================================
    def test_get_secure_path_valid(self):
        # Create dummy file inside test directory
        test_file = self.base_path / "app.log"
        test_file.touch()
        
        path = get_secure_path("app.log", self.base_path)
        self.assertEqual(path, test_file)

    def test_get_secure_path_traversal(self):
        # Attempts to escape directory via directory names
        with self.assertRaises(ValueError):
            get_secure_path("subdir/../../outside.log", self.base_path)

    def test_get_secure_path_base_dir_access(self):
        # Do not allow access to the directory itself
        with self.assertRaises(ValueError):
            get_secure_path(".", self.base_path)

    # ==========================================
    # 4. OS-Level File Security Tests
    # ==========================================
    def test_open_file_safely_directory(self):
        # Open directory as file should fail
        with self.assertRaises(ValueError):
            open_file_safely(self.base_path)

    def test_open_file_safely_not_found(self):
        with self.assertRaises(FileNotFoundError):
            open_file_safely(self.base_path / "non_existent.log")

    def test_open_file_safely_symlink(self):
        # Check if platform supports symlinks
        test_file = self.base_path / "target.log"
        test_file.touch()
        link_path = self.base_path / "link.log"
        
        try:
            os.symlink(test_file, link_path)
            # Opening symlink should trigger Security Exception
            with self.assertRaises(ValueError, msg="Failed to block symlink"):
                fd = open_file_safely(link_path)
                os.close(fd)
        except OSError:
            # Skip test if symlink creation is not permitted
            self.skipTest("OS does not support symlink creation in this environment.")

    # ==========================================
    # 5. Dynamic Response Redaction Tests
    # ==========================================
    def test_redaction_google_api_key(self):
        raw = "Error sending message: key=AIzaSyB_1234567890ABCDEFGHIJKLMNOPQRSTU, failed"
        expected = "Error sending message: key=[REDACTED API KEY], failed"
        self.assertEqual(redact_sensitive_data(raw), expected)

    def test_redaction_jwt(self):
        raw = "Session JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
        expected = "Session JWT token: [REDACTED JWT]"
        self.assertEqual(redact_sensitive_data(raw), expected)

    def test_redaction_aws_key(self):
        raw = "AWS Access Key is AKIAIOSFODNN7EXAMPLE."
        expected = "AWS Access Key is [REDACTED AWS KEY]."
        self.assertEqual(redact_sensitive_data(raw), expected)

    def test_redaction_bearer_token(self):
        raw = "Headers: Authorization: Bearer mySecretToken12345, Content-Type: json"
        expected = "Headers: Authorization: Bearer [REDACTED TOKEN], Content-Type: json"
        self.assertEqual(redact_sensitive_data(raw), expected)

    def test_redaction_key_value_secrets(self):
        test_cases = [
            ("password=super_secret_password_12345", "password=[REDACTED TOKEN]"),
            ("passwd: 'another_secret_token_123'", "passwd: '[REDACTED TOKEN]'"),
            ('{"secret": "my-vault-secret-token"}', '{"secret": "[REDACTED TOKEN]"}'),
            ("api_key = abcdef1234567890", "api_key = [REDACTED TOKEN]"),
            ("token: randomTokenString999", "token: [REDACTED TOKEN]")
        ]
        for raw, expected in test_cases:
            self.assertEqual(redact_sensitive_data(raw), expected, f"Failed on raw: {raw}")

    # ==========================================
    # 6. Tool Functional & Safeguard Tests
    # ==========================================
    def test_list_log_files(self):
        # Create safe files
        (self.base_path / "a.log").touch()
        (self.base_path / "c.log").touch()
        (self.base_path / "b.log").touch()
        # Directories should be excluded
        os.mkdir(self.base_path / "nested_dir")
        
        files = list_log_files()
        self.assertEqual(files, ["a.log", "b.log", "c.log"])

    def test_view_log_summary_valid(self):
        new_config = dataclasses.replace(server.Config, MAX_PREVIEW_LINES=3)
        with mock.patch('server.Config', new_config):
            log_content = (
                "Line 1: Normal system message\n"
                "Line 2: Service token generated: AIzaSyB_1234567890ABCDEFGHIJKLMNOPQRSTU\n"
                "Line 3: password=supersecretpass\n"
                "Line 4: System boot successful\n"
            )
            log_file = self.base_path / "system.log"
            log_file.write_text(log_content, encoding="utf-8")
            
            summary = view_log_summary("system.log")
            self.assertEqual(summary["filename"], "system.log")
            self.assertEqual(summary["line_count"], 4)
            self.assertEqual(summary["size_bytes"], os.path.getsize(log_file))
            
            expected_preview = (
                "Line 1: Normal system message\n"
                "Line 2: Service token generated: [REDACTED API KEY]\n"
                "Line 3: password=[REDACTED TOKEN]"
            )
            self.assertEqual(summary["preview"], expected_preview)

    def test_view_log_summary_size_limit(self):
        new_config = dataclasses.replace(server.Config, MAX_FILE_SIZE_BYTES=5 * 1024)  # 5KB
        with mock.patch('server.Config', new_config):
            log_file = self.base_path / "large.log"
            fd = os.open(log_file, os.O_WRONLY | os.O_CREAT)
            try:
                os.write(fd, b"A" * (6 * 1024))
            finally:
                os.close(fd)
                
            with self.assertRaises(ValueError):
                view_log_summary("large.log")

    def test_search_error_patterns_valid(self):
        log_content = (
            "Line 1: [INFO] Auth service started\n"
            "Line 2: [ERROR] Failed password for admin\n"
            "Line 3: [INFO] Token created: AIzaSyB_1234567890ABCDEFGHIJKLMNOPQRSTU\n"
            "Line 4: [ERROR] DB connection timed out\n"
            "Line 5: [INFO] Safe message\n"
        )
        log_file = self.base_path / "auth.log"
        log_file.write_text(log_content, encoding="utf-8")
        
        results = search_error_patterns("auth.log", "ERROR")
        expected = (
            "Line 2: Line 2: [ERROR] Failed password for admin\n"
            "Line 4: Line 4: [ERROR] DB connection timed out"
        )
        self.assertEqual(results, expected)

    def test_search_error_patterns_redaction(self):
        log_content = (
            "Line 1: [ERROR] Failed token: AIzaSyB_1234567890ABCDEFGHIJKLMNOPQRSTU\n"
            "Line 2: [ERROR] admin_token = secretpassword\n"
        )
        log_file = self.base_path / "auth.log"
        log_file.write_text(log_content, encoding="utf-8")
        
        results = search_error_patterns("auth.log", "ERROR")
        self.assertNotIn("AIza", results)
        self.assertNotIn("secretpassword", results)
        self.assertIn("[REDACTED API KEY]", results)
        self.assertIn("admin_token = [REDACTED TOKEN]", results)

    def test_search_error_patterns_truncation_results(self):
        new_config = dataclasses.replace(server.Config, MAX_SEARCH_RESULTS=2)
        with mock.patch('server.Config', new_config):
            log_content = (
                "[ERROR] Match 1\n"
                "[ERROR] Match 2\n"
                "[ERROR] Match 3\n"
            )
            log_file = self.base_path / "auth.log"
            log_file.write_text(log_content, encoding="utf-8")
            
            results = search_error_patterns("auth.log", "ERROR")
            
            # Should contain first 2 matches and the truncation warning
            self.assertIn("Match 1", results)
            self.assertIn("Match 2", results)
            self.assertNotIn("Match 3", results)
            self.assertIn("[WARNING: Results truncated. Showing first 2 of 3 total matches found.]", results)

    def test_search_error_patterns_truncation_chars(self):
        new_config = dataclasses.replace(server.Config, MAX_SEARCH_PAYLOAD_CHARS=50)
        with mock.patch('server.Config', new_config):
            log_content = (
                "[ERROR] Match 1 with long message\n"
                "[ERROR] Match 2 with long message\n"
            )
            log_file = self.base_path / "auth.log"
            log_file.write_text(log_content, encoding="utf-8")
            
            results = search_error_patterns("auth.log", "ERROR")
            
            self.assertIn("Match 1", results)
            self.assertNotIn("Match 2", results)
            self.assertIn("[WARNING: Results truncated. Showing first 1 of 2 total matches found.]", results)

    def test_invalid_input_cannot_inject_log_line(self):
        with self.assertRaises(ValueError):
            search_error_patterns("auth.log", "ERROR\n2026-07-18 - secure_log_analyzer - INFO - status=success")

    def test_single_oversized_line_is_truncated(self):
        new_config = dataclasses.replace(server.Config, MAX_LINE_CHARS=10)
        with mock.patch('server.Config', new_config):
            log_content = "[ERROR] A very long line that exceeds the ten character limit"
            log_file = self.base_path / "long.log"
            log_file.write_text(log_content, encoding="utf-8")
            
            results = search_error_patterns("long.log", "ERROR")
            self.assertIn("[ERROR] A … [LINE TRUNCATED]", results)

    def test_size_validation_uses_open_file_descriptor(self):
        log_file = self.base_path / "fstat.log"
        log_file.write_text("Small file", encoding="utf-8")
        
        original_fstat = os.fstat
        def mock_fstat(fd):
            res = original_fstat(fd)
            mock_stat = mock.MagicMock()
            mock_stat.st_mode = res.st_mode
            mock_stat.st_size = server.Config.MAX_FILE_SIZE_BYTES + 1000
            return mock_stat

        with mock.patch('os.fstat', side_effect=mock_fstat):
            with self.assertRaises(ValueError) as context:
                view_log_summary("fstat.log")
            self.assertIn("Failed to open or validate the log file.", str(context.exception))

    def test_non_regular_file_is_rejected(self):
        log_file = self.base_path / "nonreg.log"
        log_file.write_text("Hello", encoding="utf-8")
        
        original_fstat = os.fstat
        def mock_fstat(fd):
            res = original_fstat(fd)
            mock_stat = mock.MagicMock()
            mock_stat.st_mode = 0  # 0 means not a regular file (e.g. FIFO/socket)
            mock_stat.st_size = res.st_size
            return mock_stat

        with mock.patch('os.fstat', side_effect=mock_fstat):
            with self.assertRaises(ValueError) as context:
                view_log_summary("nonreg.log")
            self.assertEqual(str(context.exception), "Failed to open or validate the log file.")

    def test_empty_file_summary(self):
        log_file = self.base_path / "empty.log"
        log_file.touch()
        
        summary = view_log_summary("empty.log")
        self.assertEqual(summary["size_bytes"], 0)
        self.assertEqual(summary["line_count"], 0)
        self.assertEqual(summary["preview"], "")
        self.assertFalse(summary["preview_truncated"])

    def test_case_insensitive_search(self):
        log_file = self.base_path / "case.log"
        log_file.write_text("[Error] Mixed Case\n[ERROR] UPPERCASE\n[error] lowercase\n", encoding="utf-8")
        
        # Searching for "error" should match all three
        results = search_error_patterns("case.log", "eRrOr")
        self.assertIn("Mixed Case", results)
        self.assertIn("UPPERCASE", results)
        self.assertIn("lowercase", results)

    def test_no_match_response_does_not_leak_unsafe_input(self):
        log_file = self.base_path / "nomatch.log"
        log_file.write_text("Safe line\n", encoding="utf-8")
        
        keyword = "NO_MATCH_AT_ALL"
        results = search_error_patterns("nomatch.log", keyword)
        self.assertEqual(results, f"No matches found for keyword '{keyword}' in 'nomatch.log'.")
        
    def test_preview_explicitly_indicates_truncation(self):
        new_config = dataclasses.replace(server.Config, MAX_PREVIEW_LINES=2)
        with mock.patch('server.Config', new_config):
            log_file = self.base_path / "preview.log"
            log_file.write_text("Line 1\nLine 2\nLine 3\n", encoding="utf-8")
            
            summary = view_log_summary("preview.log")
            self.assertEqual(summary["line_count"], 3)
            self.assertTrue(summary["preview_truncated"])

    # ==========================================
    # 7. End-to-End Security Rejection Tests
    # ==========================================
    def test_view_log_summary_rejects_path_traversal(self):
        """Evaluator scenario: trying to read files outside the safe directory."""
        malicious_filenames = ["../server.py", "..\\server.py", "../../etc/passwd"]
        for name in malicious_filenames:
            with self.assertRaises(ValueError, msg=f"Failed to reject traversal via view_log_summary: {name}"):
                view_log_summary(name)

    def test_search_error_patterns_rejects_path_traversal(self):
        """Evaluator scenario: trying to search files outside the safe directory."""
        with self.assertRaises(ValueError):
            search_error_patterns("../../etc/shadow", "ERROR")

    def test_search_error_patterns_rejects_shell_injection(self):
        """Evaluator scenario: trying to inject shell commands via keyword."""
        log_file = self.base_path / "safe.log"
        log_file.write_text("[ERROR] test\n", encoding="utf-8")
        
        payloads = ["ERROR; cat /etc/passwd", "ERROR && whoami", "ERROR | nc -l 4444"]
        for payload in payloads:
            with self.assertRaises(ValueError, msg=f"Failed to reject shell injection: {payload}"):
                search_error_patterns("safe.log", payload)

if __name__ == "__main__":
    unittest.main()