# Engineering Note: AI Development Approach & Security Architecture

This document details the development approach and security trade-offs considered during the design and implementation of the Secure File & Log Analyzer MCP Server.

## 🤖 AI Development Approach

Developing a security-sensitive application requires close collaboration with AI agents to ensure code correctness and robust edge-case coverage:

1. **Collaborative Pattern Engineering**: 
   - We iteratively designed bounded regex patterns for common credential formats and validated them against synthetic positive and negative cases.
   - We designed a unified scanner for key-value configurations, iterating to match arbitrary alphanumeric and hyphenated/underscored prefixes (e.g., `auth_token`, `session_secret`) instead of just literal word boundaries.
   - AI assistance was used to challenge the initial threat model, generate adversarial test cases, and propose candidate redaction patterns. Each suggestion was manually reviewed and validated through tests.

2. **Mock Data Schema Design**:
   - AI was used to generate realistic, multi-service mock log files that mirror production infrastructure patterns (API gateways, auth services, system daemons).
   - Each mock log was deliberately designed to embed a mix of credential types (Google API keys, JWTs, AWS access keys, Bearer tokens, inline passwords) within `ERROR` and `CRITICAL` log lines, so that the search tool naturally triggers redaction — creating a clear, demonstrable test surface.
   - The format (timestamps, service tags, severity levels, structured key-value payloads) was chosen to be representative of real-world log output, making the server's behavior testable against plausible data.

3. **Iterative Security Hardening**: 
   - **Symlink TOCTOU Mitigation**: We recognized that `Path.is_symlink()` creates a Time-of-Check to Time-of-Use (TOCTOU) race condition. We addressed this by integrating native kernel-level protections (e.g., `os.O_NOFOLLOW` on Unix). 
   - *Note on Windows support*: While Python standard library guarantees for TOCTOU are weaker on Windows, our implementation attempts handle-level validation. However, production deployments should ultimately combine this application validation with proper container sandboxing.

4. **Security Trade-off Analysis**:
   - AI was used as a sounding board to evaluate the trade-offs between application-level path validation versus OS-level sandboxing, informing the defense-in-depth architecture documented below.

## ⚖️ Security Trade-offs: Code Validation vs. OS Sandboxing

Securing file access requires understanding the trade-offs at different layers of the computing stack.

### 1. Application-Level Validation (In-Code)
Our server implements strict in-code path normalization, character allow-listing, and file handle verification.
* **Advantages**: Zero deployment overhead, granular control (content-aware redaction), and high portability.
* **Limitations**: Relies on developers anticipating every evasion technique (unicode, traversal sequences). The process runs with user privileges, exposing files if validation is bypassed.

### 2. OS-Level Sandboxing (Isolated Environment)
The server runs inside an isolated container (Docker, gVisor) where the filesystem is virtualized.
* **Advantages**: Kernel-enforced isolation. Even with a path validation bypass, the attacker is trapped. Logs can be mounted read-only, and system calls (`seccomp`) can be aggressively filtered.
* **Limitations**: Operational complexity, configuration overhead, and higher resource utilization.

### Conclusion: Defense-in-Depth
Application-level validation and OS-level sandboxing are complementary. Code validation prevents logic abuse, while sandboxes contain catastrophic failures. In production, this MCP server should be deployed inside a **minimal, rootless container with the logs directory mounted read-only**, while maintaining the rigorous code-level sanitization implemented here.
