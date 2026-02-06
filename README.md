# cargo-panic-audit

**Find panic patterns that can take down production Rust services**

A production-focused static analysis tool that identifies 8 critical classes of panic patterns in Rust code - from assumption failures to cascading outages.

## Why This Matters

**On July 2, 2019, a single `unwrap()` took down Cloudflare globally for 27 minutes.**

A regex compilation failure during config parsing caused an `unwrap()` to panic. Because this happened in a critical path without error handling, it crashed their entire edge network - **taking down 5% of global internet traffic**.

[Read the Cloudflare postmortem →](https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/)

### The Pattern (Class 4: Cloudflare-Class)

```rust
// ⚠️ This exact pattern caused the outage
let config = std::fs::read_to_string("features.toml").unwrap();
let parsed = toml::from_str(&config).unwrap();  // Regex compilation failed here
let regex = Regex::new(&parsed.pattern).unwrap();  // PANIC → Global outage
```

**cargo-panic-audit detects this pattern and 7 other critical panic classes** that can cause production incidents.

### Real-World Impact

Panics in production Rust services can cause:
- 🔴 **Cascading failures** - One panic poisons mutexes, bringing down all threads
- 🔴 **Service outages** - Unhandled panics crash request handlers
- 🔴 **Data corruption** - Panics in Drop implementations leave inconsistent state
- 🔴 **Amplification attacks** - Malicious input triggers panics across your fleet

## Features

- 🔍 **8 Panic Classes** - From basic unwraps to Cloudflare-class config loading failures
- 🎯 **Severity-Based** - Critical, High, Medium, Low risk classification
- 📊 **Multiple Output Formats** - Human-readable, JSON, summary mode
- 🚀 **Fast Scanning** - AST-based analysis with syn
- 📦 **Direct crates.io Integration** - Download and audit any published crate
- 🎨 **Rich CLI** - Colored output, detailed explanations, verbose modes

## Installation

```bash
cargo install cargo-panic-audit
```

Or build from source:

```bash
git clone https://github.com/vasusrini/cargo-panic-audit
cd cargo-panic-audit
cargo build --release
```

## Quick Start

```bash
# Audit a crate from crates.io
cargo-panic-audit tokio

# Scan your local project
cargo-panic-audit . --local

# Show detailed explanations
cargo-panic-audit . --local --verbose
```

## What We Detect

### 8 Critical Panic Classes

#### 1. **Assumption Panics** 
`unwrap()`, `expect()`, `unwrap_unchecked()`

Flags logic that assumes "this can't fail" on real-world input.

```rust
// 🔴 CRITICAL: File I/O can fail
let config = File::open("config.json").unwrap();

// ✅ SAFE: Handle errors
let config = File::open("config.json")?;
```

#### 2. **Implicit Panics**
Indexing `[i]`, `todo!()`, `unimplemented!()`

Panics hidden in normal-looking code.

```rust
// 🔴 CRITICAL: Index out of bounds
let item = items[user_input];

// ✅ SAFE: Bounds checking
let item = items.get(user_input)?;
```

#### 3. **Panic Amplification**
`Mutex::lock().unwrap()`, panics in Drop

Single panic → cascading failure across threads.

```rust
// 🔴 CRITICAL: One panic poisons all threads
let data = self.mutex.lock().unwrap();

// ✅ SAFE: Handle poisoned mutex
let data = self.mutex.lock().unwrap_or_else(|e| e.into_inner());
```

#### 4. **Cloudflare-Class**
Deserialization + size/bounds + unwrap

The exact pattern that caused Cloudflare's global outage.

```rust
// 🔴 CRITICAL: Cloudflare pattern
let config = std::fs::read_to_string("features.toml").unwrap();
let parsed: Config = toml::from_str(&config).unwrap();

// ✅ SAFE: Proper error handling
let config = std::fs::read_to_string("features.toml")
    .context("Failed to read config")?;
let parsed: Config = toml::from_str(&config)
    .context("Invalid config format")?;
```

#### 5. **Assertion Failures**
`assert!()` in non-test code

Turns unexpected input into crashes.

```rust
// 🔴 MEDIUM: Assertions can fail
assert!(value >= 0 && value <= 100);

// ✅ SAFE: Return errors
if value < 0 || value > 100 {
    return Err("Value out of range");
}
```

#### 6. **Allocation & OOM**
`Vec::with_capacity(untrusted)`

Memory-driven panics and restarts.

```rust
// 🔴 HIGH: User controls allocation size
let buf = Vec::with_capacity(user_size);

// ✅ SAFE: Limit and validate
const MAX_SIZE: usize = 1_000_000;
if user_size > MAX_SIZE {
    return Err("Size too large");
}
```

#### 7. **FFI Boundary Panics**
Panics in `extern "C"` paths

Can abort the entire process.

```rust
// 🔴 CRITICAL: Panic across FFI boundary
#[no_mangle]
pub extern "C" fn process(data: *const u8) {
    let slice = unsafe { std::slice::from_raw_parts(data, 100) };
    let value = slice[0]; // Can panic!
}
```

#### 8. **Process-Killing Calls**
`std::process::exit()` in libraries

One code path kills the whole service.

```rust
// 🔴 CRITICAL: Library shouldn't exit process
pub fn handle_error(err: Error) {
    eprintln!("Fatal error: {}", err);
    std::process::exit(1); // Kills entire application!
}

// ✅ SAFE: Return errors
pub fn handle_error(err: Error) -> Result<(), Error> {
    Err(err)
}
```

## Usage


### Basic Audit (from crates.io)

```bash
# Audit the latest version of a crate
cargo-panic-audit tokio

# Audit a specific version
cargo-panic-audit serde 1.0.150

# Show detailed explanations of what's detected
cargo-panic-audit actix-web --explain

# Verbose mode (show all findings including low-risk)
cargo-panic-audit tokio --verbose
```

### Scanning Local Crates / Workspace

```bash
# Scan current directory
cargo-panic-audit . --local

# Scan a specific crate in your workspace
cargo-panic-audit ./crates/my-app --local

# Scan workspace member
cd my-workspace
cargo-panic-audit ./my-api --local --verbose

# Scan entire workspace (scan each member)
for crate in crates/*; do
  cargo-panic-audit "$crate" --local
done
```

### In a Makefile or Just

```makefile
# Makefile
audit-local:
	cargo-panic-audit . --local --fail-on-findings

audit-all-crates:
	@for dir in crates/*; do \
		echo "Auditing $$dir..."; \
		cargo-panic-audit "$$dir" --local; \
	done
```

```justfile
# Justfile
audit-local:
    cargo-panic-audit . --local --fail-on-findings

audit-all:
    #!/usr/bin/env bash
    for crate in crates/*; do
        echo "Auditing $crate..."
        cargo-panic-audit "$crate" --local
    done
```

### Output Formats

```bash
# JSON output (for CI/CD integration)
cargo-panic-audit hyper --json

# Summary only
cargo-panic-audit reqwest --summary

# Show rule legend
cargo-panic-audit --legend
```

### CI/CD Integration

```bash
# Fail build if critical findings exist
cargo-panic-audit my-crate --fail-on-findings
```

## What We Detect

### 8 Critical Panic Classes

1. **Assumption Panics** - `unwrap()`, `expect()`, `unwrap_unchecked()`
   - Flags logic that assumes "this can't fail" on real-world input

2. **Implicit Panics** - Indexing `[i]`, `todo!()`, `unimplemented!()`
   - Panics hidden in normal-looking code

3. **Panic Amplification** - `Mutex::lock().unwrap()`, panics in Drop
   - Single panic → cascading failure across threads

4. **Cloudflare-Class** - Deserialization + size/bounds + unwrap
   - The exact pattern that caused Cloudflare's global outage

5. **Assertion Failures** - `assert!()` in non-test code
   - Turns unexpected input into crashes

6. **Allocation & OOM** - `Vec::with_capacity(untrusted)`
   - Memory-driven panics and restarts

7. **FFI Boundary Panics** - Panics in `extern "C"` paths
   - Can abort the entire process

8. **Process-Killing Calls** - `std::process::exit()` in libraries
   - One code path kills the whole service

### Severity Levels

- 🔴 **CRITICAL** - Can cause cascading outages (Cloudflare-class)
  - Examples: External I/O, network, config loading, panic amplification
  - Action: Add error handling, implement fallback, return Result

- 🟠 **HIGH** - Can crash request handlers or worker threads
  - Examples: Parsing untrusted data, database ops, large allocations
  - Action: Validate input, return Result, add size limits

- 🟡 **MEDIUM** - Can fail under specific runtime conditions
  - Examples: Environment variables, assertions, array indexing
  - Action: Provide defaults, add bounds checking, validate assumptions

- ⚪ **LOW** - Low-risk internal operations
  - Examples: Arc unwrap, internal field access, after explicit validation
  - Action: Review context - usually intentional and safe

## Architecture

```
cargo-panic-audit/
├── src/
│   ├── main.rs           # Entry point, orchestration
│   ├── cli.rs            # Argument parsing (clap)
│   ├── types.rs          # Severity, PanicClass, Vulnerability types
│   ├── rules.rs          # Rule definitions and classification logic
│   ├── scanner.rs        # AST visitor implementation (syn)
│   ├── audit.rs          # File system scanning
│   ├── download.rs       # crates.io integration
│   └── report.rs         # Output formatting
└── Cargo.toml
```

### Key Components

- **Scanner** - AST visitor that detects panic patterns
- **Rules Engine** - Classifies patterns by severity and risk
- **Reporter** - Flexible output (human-readable, JSON, summary)
- **Downloader** - Fetches and extracts crates from crates.io

## Example Output

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║  cargo-panic-audit v0.5.0                                                     ║
║  Find panic patterns that can take down production Rust services              ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

📥 Downloading tokio v1.49.0...
📦 Extracting...
🔍 Auditing for production panic patterns...
   Scanning 536 Rust source files

🧹 Cleaning up...

════════════════════════════════════════════════════════════════════════════════
AUDIT REPORT: tokio v1.49.0
════════════════════════════════════════════════════════════════════════════════

⚠️  3 panic patterns detected:

   🟡 Medium:   3 (Conditional failures)

SEVERITY LEVELS & ACTIONS
────────────────────────────────────────────────────────────────────────────────

  🔴 CRITICAL - Can cause cascading outages (Cloudflare-class)
     Examples: External I/O, network, config loading, panic amplification
     Action: Add error handling, implement fallback, return Result

  🟠 HIGH - Can crash request handlers or worker threads
     Examples: Parsing untrusted data, database ops, large allocations
     Action: Validate input, return Result, add size limits

  🟡 MEDIUM - Can fail under specific runtime conditions
     Examples: Environment variables, assertions, array indexing
     Action: Provide defaults, add bounds checking, validate assumptions

  ⚪ LOW - Low-risk internal operations
     Examples: Arc unwrap, internal field access, after explicit validation
     Action: Review context - usually intentional and safe

════════════════════════════════════════════════════════════════════════════════

✅ Audit complete!
   No critical issues found, but review high/medium patterns.
```

## Rule IDs

```
PA001 | unwrap          | HIGH     | Use of unwrap() may panic
PA002 | expect          | HIGH     | Use of expect() may panic
PA003 | panic           | CRITICAL | panic! macro found
PA004 | todo            | MEDIUM   | todo! macro found
PA005 | unreachable     | MEDIUM   | unreachable! macro found
PA006 | indexing        | MEDIUM   | Array/slice indexing may panic
PA007 | assertion       | MEDIUM   | Assertion may fail
PA008 | mutex_unwrap    | CRITICAL | Mutex/RwLock unwrap (panic amplification)
PA009 | process_exit    | CRITICAL | process::exit() found
```

## Contributing

Contributions welcome! Please open an issue or PR.

## License

MIT OR Apache-2.0

## Credits

Inspired by production incidents and the need for better panic pattern detection in Rust codebases.
