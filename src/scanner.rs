use crate::rules::{classify_panic, is_false_positive};
use crate::types::{PanicClass, Severity, Vulnerability};
use quote::quote;
use syn::{visit::Visit, ExprIndex, ExprMethodCall, ItemFn, Macro};

pub struct Scanner {
    #[allow(dead_code)]
    pub crate_name: String,
    pub current_file: String,
    pub current_source: String,  // Store source content for line lookup
    pub in_test_code: bool,
    #[allow(dead_code)]
    pub in_unsafe_block: bool,
    pub in_extern_fn: bool,
    pub vulnerabilities: Vec<Vulnerability>,
}

impl Scanner {
    pub fn new(crate_name: String) -> Self {
        Self {
            crate_name,
            current_file: String::new(),
            current_source: String::new(),
            in_test_code: false,
            in_unsafe_block: false,
            in_extern_fn: false,
            vulnerabilities: Vec::new(),
        }
    }

    /// Extract line number from quote! output by searching source
    fn find_line_in_source(&self, code_snippet: &str) -> usize {
        // Remove whitespace and normalize the snippet for searching
        let normalized_snippet: String = code_snippet
            .chars()
            .filter(|c| !c.is_whitespace())
            .take(40) // First 40 non-whitespace chars for matching
            .collect();
        
        if normalized_snippet.is_empty() {
            return 1;
        }

        // Search through source lines
        for (line_num, line) in self.current_source.lines().enumerate() {
            let normalized_line: String = line
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            
            if normalized_line.contains(&normalized_snippet) {
                return line_num + 1; // Line numbers are 1-indexed
            }
        }
        
        1 // Default to line 1 if not found
    }

    pub fn check_assumption_panic(&mut self, code: &str, _method: &str, line: usize) {
        if is_false_positive(code) {
            return;
        }

        let (severity, panic_class, pattern) = classify_panic(code);
        
        self.vulnerabilities.push(Vulnerability::new(
            self.current_file.clone(),
            line.to_string(),
            severity,
            panic_class,
            pattern,
            code.chars().take(120).collect(),
        ));
    }

    pub fn check_panic_amplification(&mut self, code: &str, line: usize) {
        let lower = code.to_lowercase();
        
        // Class 3: Mutex/RwLock unwrap (panic amplification)
        if (lower.contains("mutex") || lower.contains("rwlock")) &&
           (lower.contains("lock(") || lower.contains("read(") || lower.contains("write(")) {
            
            self.vulnerabilities.push(Vulnerability::new(
                self.current_file.clone(),
                line.to_string(),
                Severity::Critical,
                PanicClass::PanicAmplification,
                "Mutex/RwLock unwrap (panic amplification)".to_string(),
                code.chars().take(120).collect(),
            ));
        }
    }
}

impl<'ast> Visit<'ast> for Scanner {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let was_in_test = self.in_test_code;
        let was_in_extern = self.in_extern_fn;
        
        // Check if test function
        self.in_test_code = node.attrs.iter().any(|attr| {
            if let Some(ident) = attr.path().get_ident() {
                matches!(ident.to_string().as_str(), "test" | "bench")
            } else {
                false
            }
        });

        // Check if extern "C" function
        if let Some(abi) = &node.sig.abi {
            if abi.name.is_some() {
                self.in_extern_fn = true;
            }
        }

        syn::visit::visit_item_fn(self, node);
        self.in_test_code = was_in_test;
        self.in_extern_fn = was_in_extern;
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();

        if !self.in_test_code && !self.current_file.contains("/tests/") {
            let code = quote!(#node).to_string();
            let line = self.find_line_in_source(&code);

            // Class 1: Assumption panics
            if matches!(method.as_str(), "unwrap" | "expect" | "unwrap_unchecked") {
                self.check_assumption_panic(&code, &method, line);
            }

            // Class 3: Panic amplification (Mutex/RwLock unwrap)
            if method == "unwrap" || method == "expect" {
                self.check_panic_amplification(&code, line);
            }
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_index(&mut self, node: &'ast ExprIndex) {
        if !self.in_test_code && !self.current_file.contains("/tests/") {
            // Class 2: Implicit panics (indexing)
            let code = quote!(#node).to_string();
            let line = self.find_line_in_source(&code);
            
            self.vulnerabilities.push(Vulnerability::new(
                self.current_file.clone(),
                line.to_string(),
                Severity::Medium,
                PanicClass::ImplicitPanic,
                "Array/Slice Indexing".to_string(),
                code.chars().take(120).collect(),
            ));
        }

        syn::visit::visit_expr_index(self, node);
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        if !self.in_test_code && !self.current_file.contains("/tests/") {
            let macro_name = node.path.segments.last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();

            let code = quote!(#node).to_string();
            let line = self.find_line_in_source(&code);

            match macro_name.as_str() {
                // Class 2: Implicit panics
                "todo" | "unimplemented" => {
                    self.vulnerabilities.push(Vulnerability::new(
                        self.current_file.clone(),
                        line.to_string(),
                        Severity::Critical,
                        PanicClass::ImplicitPanic,
                        format!("{}!()", macro_name),
                        code.chars().take(120).collect(),
                    ));
                }
                
                // Class 5: Assertion failures
                "assert" | "assert_eq" | "assert_ne" | "debug_assert" => {
                    self.vulnerabilities.push(Vulnerability::new(
                        self.current_file.clone(),
                        line.to_string(),
                        Severity::Medium,
                        PanicClass::AssertionFailure,
                        format!("{}!()", macro_name),
                        code.chars().take(120).collect(),
                    ));
                }

                // Class 8: Process-killing
                "exit" if code.contains("std::process") => {
                    self.vulnerabilities.push(Vulnerability::new(
                        self.current_file.clone(),
                        line.to_string(),
                        Severity::Critical,
                        PanicClass::ProcessKilling,
                        "process::exit()".to_string(),
                        code.chars().take(120).collect(),
                    ));
                }
                
                _ => {}
            }
        }

        syn::visit::visit_macro(self, node);
    }
}