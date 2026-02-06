use serde::Serialize;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Serialize)]
pub enum Severity {
    Critical,  // Can cause cascading outages
    High,      // Can crash request handlers
    Medium,    // Can fail under specific conditions
    Low,       // Low-risk internal operations
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum PanicClass {
    // Class 1: Assumption panics
    AssumptionPanic,
    
    // Class 2: Implicit panics
    ImplicitPanic,
    
    // Class 3: Panic amplification
    PanicAmplification,
    
    // Class 4: Cloudflare-class (deserialization + limits)
    CloudflareClass,
    
    // Class 5: Assertion failures
    AssertionFailure,
    
    // Class 6: Allocation/OOM
    AllocationPanic,
    
    // Class 7: FFI boundary (reserved for future use)
    #[allow(dead_code)]
    FFIBoundary,
    
    // Class 8: Process-killing
    ProcessKilling,
}

#[derive(Debug, Serialize)]
pub struct Vulnerability {
    pub file: String,
    pub line: String,
    pub severity: Severity,
    pub panic_class: PanicClass,
    pub pattern: String,
    pub code: String,
}

impl Vulnerability {
    pub fn new(
        file: String,
        line: String,
        severity: Severity,
        panic_class: PanicClass,
        pattern: String,
        code: String,
    ) -> Self {
        Self {
            file,
            line,
            severity,
            panic_class,
            pattern,
            code,
        }
    }
}