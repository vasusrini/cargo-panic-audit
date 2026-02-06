use crate::types::{PanicClass, Severity};

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: &'static str,
    pub kind: &'static str,
    pub severity: &'static str,
    pub message: &'static str,
}

pub const RULE_UNWRAP: Rule = Rule {
    id: "PA001",
    kind: "unwrap",
    severity: "HIGH",
    message: "Use of unwrap() may panic",
};

pub const RULE_EXPECT: Rule = Rule {
    id: "PA002",
    kind: "expect",
    severity: "HIGH",
    message: "Use of expect() may panic",
};

pub const RULE_PANIC: Rule = Rule {
    id: "PA003",
    kind: "panic",
    severity: "CRITICAL",
    message: "panic! macro found",
};

pub const RULE_TODO: Rule = Rule {
    id: "PA004",
    kind: "todo",
    severity: "MEDIUM",
    message: "todo! macro found",
};

pub const RULE_UNREACHABLE: Rule = Rule {
    id: "PA005",
    kind: "unreachable",
    severity: "MEDIUM",
    message: "unreachable! macro found",
};

pub const RULE_INDEXING: Rule = Rule {
    id: "PA006",
    kind: "indexing",
    severity: "MEDIUM",
    message: "Array/slice indexing may panic",
};

pub const RULE_ASSERTION: Rule = Rule {
    id: "PA007",
    kind: "assertion",
    severity: "MEDIUM",
    message: "Assertion may fail",
};

pub const RULE_MUTEX_UNWRAP: Rule = Rule {
    id: "PA008",
    kind: "mutex_unwrap",
    severity: "CRITICAL",
    message: "Mutex/RwLock unwrap (panic amplification)",
};

pub const RULE_PROCESS_EXIT: Rule = Rule {
    id: "PA009",
    kind: "process_exit",
    severity: "CRITICAL",
    message: "process::exit() found",
};

pub fn all_rules() -> &'static [Rule] {
    &[
        RULE_UNWRAP,
        RULE_EXPECT,
        RULE_PANIC,
        RULE_TODO,
        RULE_UNREACHABLE,
        RULE_INDEXING,
        RULE_ASSERTION,
        RULE_MUTEX_UNWRAP,
        RULE_PROCESS_EXIT,
    ]
}

pub fn classify_panic(code: &str) -> (Severity, PanicClass, String) {
    let lower = code.to_lowercase();

    // Class 4: Cloudflare-class (config/feature file loading)
    if is_cloudflare_class(&lower) {
        return (
            Severity::Critical,
            PanicClass::CloudflareClass,
            "Config/Feature File Loading (Cloudflare Pattern)".to_string(),
        );
    }

    // Critical I/O operations
    if (lower.contains("file::open") || 
        lower.contains("file::create") ||
        lower.contains("fs::read") ||
        lower.contains("fs::write") ||
        lower.contains("read_to_string")) &&
       (lower.contains("unwrap") || lower.contains("expect")) {
        return (
            Severity::Critical,
            PanicClass::AssumptionPanic,
            "File I/O Operation".to_string()
        );
    }

    // Network operations
    if (lower.contains("tcpstream::connect") ||
        lower.contains("tcplistener::bind") ||
        lower.contains("udpsocket::bind")) &&
       (lower.contains("unwrap") || lower.contains("expect")) {
        return (
            Severity::Critical,
            PanicClass::AssumptionPanic,
            "Network Socket Operation".to_string()
        );
    }

    // HTTP client operations
    if (lower.contains("reqwest") || lower.contains("hyper")) &&
       lower.contains(".send(") {
        return (
            Severity::Critical,
            PanicClass::AssumptionPanic,
            "HTTP Request".to_string()
        );
    }

    // Class 6: Allocation with untrusted size
    if lower.contains("with_capacity") || lower.contains("reserve") {
        return (
            Severity::High,
            PanicClass::AllocationPanic,
            "Allocation with Potential Untrusted Size".to_string()
        );
    }

    // Parsing operations
    if lower.contains("str::parse") ||
        lower.contains(".parse::<") ||
        lower.contains("from_str(") ||
        lower.contains("serde_json::from") ||
        lower.contains("toml::from") ||
        lower.contains("yaml::from") {
        return (
            Severity::High,
            PanicClass::AssumptionPanic,
            "Parsing Operation".to_string()
        );
    }

    // Database operations
    if (lower.contains("query(") || 
        lower.contains("execute(") ||
        lower.contains("fetch")) &&
       (lower.contains("diesel") || 
        lower.contains("sqlx") ||
        lower.contains("postgres")) {
        return (
            Severity::High,
            PanicClass::AssumptionPanic,
            "Database Operation".to_string()
        );
    }

    // Environment variables
    if lower.contains("env::var") {
        return (
            Severity::Medium,
            PanicClass::AssumptionPanic,
            "Environment Variable".to_string()
        );
    }

    (
        Severity::Low,
        PanicClass::AssumptionPanic,
        "General Unwrap".to_string()
    )
}

fn is_cloudflare_class(code: &str) -> bool {
    let has_file_op = code.contains("file::open") ||
                      code.contains("read_to_string") ||
                      code.contains("fs::read");
    
    let config_keywords = [".toml", ".yaml", ".json", ".ini", ".conf", 
                          "config", "settings", "feature"];
    let has_config = config_keywords.iter().any(|kw| code.contains(kw));
    
    has_file_op && has_config
}

pub fn is_false_positive(code: &str) -> bool {
    let lower = code.to_lowercase();
    
    // Filter false positives
    if lower.contains("arc::try_unwrap") || 
       lower.contains("rc::try_unwrap") {
        return true; // Memory management, not I/O
    }
    
    if (lower.contains("self.inner") || lower.contains(".inner()")) && 
       !lower.contains("file") && !lower.contains("read") && !lower.contains("load") {
        return true; // Internal field access
    }

    false
}
