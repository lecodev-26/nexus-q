#![feature(rustc_private)]
#![allow(unused_extern_crates)]

dylint_linting::dylint_library!();

extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_lint_defs;
extern crate rustc_session;

use rustc_hir::{BinOpKind, Expr, ExprKind, Item, ItemKind};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_lint_defs::{declare_lint, impl_lint_pass};

// These checks are intentionally heuristic. They flag review candidates, not proofs
// of a vulnerability. See docs/security/DYLINT_CRYPTO_RULES.md for scope and limits.
declare_lint! {
    pub NEXUSQ_CRYPTO_SECRET_COMPARISON,
    Warn,
    "ordinary equality comparison involving an identifier that looks secret-bearing"
}
declare_lint! {
    pub NEXUSQ_CRYPTO_UNWRAP_EXPECT,
    Warn,
    "unwrap or expect in a source file under a crypto module"
}
declare_lint! {
    pub NEXUSQ_CRYPTO_NONCE_LITERAL_REUSE,
    Warn,
    "repeated explicit nonce literal in encryption call sites within one item"
}

pub struct NexusqCryptoLints;
impl_lint_pass!(NexusqCryptoLints => [
    NEXUSQ_CRYPTO_SECRET_COMPARISON,
    NEXUSQ_CRYPTO_UNWRAP_EXPECT,
    NEXUSQ_CRYPTO_NONCE_LITERAL_REUSE,
]);

#[cfg_attr(not(feature = "rlib"), unsafe(no_mangle))]
pub fn register_lints(_sess: &rustc_session::Session, lint_store: &mut rustc_lint::LintStore) {
    lint_store.register_lints(&[
        NEXUSQ_CRYPTO_SECRET_COMPARISON,
        NEXUSQ_CRYPTO_UNWRAP_EXPECT,
        NEXUSQ_CRYPTO_NONCE_LITERAL_REUSE,
    ]);
    lint_store.register_late_lint_pass(Box::new(|_| Box::new(NexusqCryptoLints)));
}

impl<'tcx> LateLintPass<'tcx> for NexusqCryptoLints {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        if let ExprKind::Binary(op, lhs, rhs) = expr.kind
            && matches!(op.node, BinOpKind::Eq | BinOpKind::Ne)
            && let Ok(snippet) = cx.sess().source_map().span_to_snippet(expr.span)
        {
            if looks_secret_bearing(&snippet) {
                cx.sess().dcx().struct_span_warn(
                    expr.span,
                    "review this equality comparison: secret-bearing values should use a constant-time comparison such as `subtle::ConstantTimeEq`",
                ).emit();
            }
            let _ = (lhs, rhs);
        }

        if let ExprKind::MethodCall(segment, receiver, args, _) = expr.kind {
            let method = segment.ident.as_str();
            if matches!(method, "unwrap" | "expect") {
                let path = cx
                    .sess()
                    .source_map()
                    .span_to_filename(expr.span)
                    .to_string();
                if is_crypto_source_path(&path) {
                    cx.sess().dcx().struct_span_warn(
                        expr.span,
                        "avoid panic-based error handling in cryptographic code; propagate or map the error instead",
                    ).emit();
                }
            }
            let _ = (receiver, args);
        }
    }

    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        if !matches!(item.kind, ItemKind::Fn { .. }) {
            return;
        }
        let Ok(snippet) = cx.sess().source_map().span_to_snippet(item.span) else {
            return;
        };
        // Deliberately limited to explicit byte-string/byte-array nonce literals passed
        // in source text to common AEAD encryption calls. Variable/data-flow reuse is not
        // inferred by this first version.
        if has_reused_nonce_literals(&snippet) {
            cx.sess().dcx().struct_span_warn(
                item.span,
                "the same explicit nonce literal appears in multiple encryption call sites in this item; use a fresh nonce for each encryption under a key",
            ).emit();
        }
    }
}

fn is_crypto_source_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    normalized.contains("/crypto/") || normalized.contains("/crypto.")
}

fn looks_secret_bearing(snippet: &str) -> bool {
    let lower = snippet.to_ascii_lowercase();
    ["secret", "private_key", "privatekey", "mac", "token", "tag"]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn has_reused_nonce_literals(snippet: &str) -> bool {
    let mut seen = std::collections::HashSet::new();
    snippet.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        let encryption_call =
            lower.contains("encrypt(") || lower.contains("encrypt (") || lower.contains("seal(");
        encryption_call
            && extract_nonce_literal(line).is_some_and(|literal| !seen.insert(literal.to_owned()))
    })
}

fn extract_nonce_literal(line: &str) -> Option<&str> {
    let start = line.find("b\"")?;
    let tail = &line[start..];
    let end = tail[2..].find('"')? + 2;
    let literal = &line[start..start + end + 1];
    // This first pass treats the first explicit byte-string literal on an
    // encryption-call line as a nonce candidate; review any resulting warning.
    Some(literal)
}

#[cfg(test)]
mod tests {
    use super::{has_reused_nonce_literals, is_crypto_source_path, looks_secret_bearing};

    #[test]
    fn flags_crypto_source_paths() {
        assert!(is_crypto_source_path("crates/core/src/crypto/aead.rs"));
        assert!(is_crypto_source_path("C:\\repo\\src\\crypto.rs"));
    }

    #[test]
    fn ignores_non_crypto_source_paths() {
        assert!(!is_crypto_source_path("crates/core/src/storage/db.rs"));
        assert!(!is_crypto_source_path(
            "crates/core/tests/crypto_fixtures.rs"
        ));
    }

    #[test]
    fn flags_secret_named_equality_operands() {
        assert!(looks_secret_bearing("secret_key == candidate"));
        assert!(looks_secret_bearing("expected_mac != actual_mac"));
    }

    #[test]
    fn allows_public_value_comparisons() {
        assert!(!looks_secret_bearing("version == supported_version"));
        assert!(!looks_secret_bearing("left == right"));
    }

    #[test]
    fn flags_repeated_explicit_nonce_literal_on_encryption_lines() {
        let source = "encrypt(key, b\"same\");\nencrypt(key, b\"same\");";
        assert!(has_reused_nonce_literals(source));
    }

    #[test]
    fn allows_distinct_nonce_literals() {
        let source = "encrypt(key, b\"first\");\nencrypt(key, b\"second\");";
        assert!(!has_reused_nonce_literals(source));
    }
}
