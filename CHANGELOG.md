# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2025-02-06

### Added
- Initial release of cargo-panic-audit
- 8 critical panic pattern classes detection:
  1. Assumption Panics (unwrap, expect, unwrap_unchecked)
  2. Implicit Panics (indexing, todo!, unimplemented!)
  3. Panic Amplification (Mutex/RwLock unwrap)
  4. Cloudflare-Class Patterns (config loading + deserialization)
  5. Assertion Failures (assert! in production code)
  6. Allocation Panics (OOM scenarios)
  7. FFI Boundary Panics (extern "C" paths)
  8. Process-Killing Patterns (std::process::exit)
- Severity-based classification (Critical, High, Medium, Low)
- AST-based analysis using syn 2.0
- Direct crates.io integration for auditing published crates
- Local directory and workspace scanning
- Multiple output formats:
  - Human-readable with colored output
  - JSON for CI/CD integration
  - Summary mode for quick overview
- Intelligent false positive filtering
- Accurate line number tracking for all findings
- Rich CLI with detailed explanations
- Context-aware risk assessment
- Test code exclusion (ignores #[test] and #[bench] functions)

### Features
- Downloads and audits any crate from crates.io
- Scans local projects and workspaces
- Identifies production-critical panic patterns
- Provides actionable severity levels
- Clean, zero-warning compilation
- Fast AST-based scanning
- Comprehensive documentation

### Technical
- Built with Rust 2021 edition
- Compatible with syn 2.0
- Cross-platform support (Linux, macOS, Windows)
- Minimal dependencies
- Well-structured codebase for contributions

## [Unreleased]

### Planned
- GitHub Actions integration examples
- Configuration file support (.panic-audit.toml)
- Suppression/allowlist functionality
- More detailed JSON output with fix suggestions
- IDE integration (LSP server)
- Additional panic pattern detections
- Performance optimizations for large codebases
- Parallel file processing
- Custom rule definitions
- Interactive mode for fixing issues

---

[0.5.0]: https://github.com/YOUR_USERNAME/cargo-panic-audit/releases/tag/v0.5.0