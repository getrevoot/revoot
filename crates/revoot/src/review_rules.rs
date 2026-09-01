//! Embedded, lowest-priority language review guidance.
//!
//! Rule selection is deterministic and never grants repository content control
//! over providers, tools, execution, network access, or publication.

use globset::Glob;
use serde::Serialize;

const DEFAULT_RULE_ID: &str = "default.md";
const DEFAULT_RULE: &str = include_str!("../assets/review_rules/rule_docs/default.md");

const RULES: &[(&str, &str, &str)] = &[
    (
        "**/*.properties",
        "properties.md",
        include_str!("../assets/review_rules/rule_docs/properties.md"),
    ),
    (
        "**/*{mapper,dao}*.xml",
        "mapper_dao_xml.md",
        include_str!("../assets/review_rules/rule_docs/mapper_dao_xml.md"),
    ),
    (
        "**/pom.xml",
        "pom_xml.md",
        include_str!("../assets/review_rules/rule_docs/pom_xml.md"),
    ),
    (
        "**/build.gradle",
        "build_gradle.md",
        include_str!("../assets/review_rules/rule_docs/build_gradle.md"),
    ),
    (
        "**/package.json",
        "package_json.md",
        include_str!("../assets/review_rules/rule_docs/package_json.md"),
    ),
    (
        "**/Cargo.toml",
        "cargo_toml.md",
        include_str!("../assets/review_rules/rule_docs/cargo_toml.md"),
    ),
    (
        "**/composer.json",
        "composer_json.md",
        include_str!("../assets/review_rules/rule_docs/composer_json.md"),
    ),
    (
        "**/*.{json,json5}",
        "json.md",
        include_str!("../assets/review_rules/rule_docs/json.md"),
    ),
    (
        ".github/workflows/**/*.{yaml,yml}",
        "github_workflows.md",
        include_str!("../assets/review_rules/rule_docs/github_workflows.md"),
    ),
    (
        ".github/**/*.{yaml,yml}",
        "github_config.md",
        include_str!("../assets/review_rules/rule_docs/github_config.md"),
    ),
    (
        "**/*.{yaml,yml}",
        "yaml.md",
        include_str!("../assets/review_rules/rule_docs/yaml.md"),
    ),
    (
        "**/*.java",
        "java.md",
        include_str!("../assets/review_rules/rule_docs/java.md"),
    ),
    (
        "**/*.go",
        "go.md",
        include_str!("../assets/review_rules/rule_docs/go.md"),
    ),
    (
        "**/*.{ftl,ftlh,ftlx}",
        "freemarker.md",
        include_str!("../assets/review_rules/rule_docs/freemarker.md"),
    ),
    (
        "**/*.{hbs,mustache}",
        "handlebars_mustache.md",
        include_str!("../assets/review_rules/rule_docs/handlebars_mustache.md"),
    ),
    (
        "**/*.pug",
        "pug.md",
        include_str!("../assets/review_rules/rule_docs/pug.md"),
    ),
    (
        "**/*.ets",
        "arkts.md",
        include_str!("../assets/review_rules/rule_docs/arkts.md"),
    ),
    (
        "**/*.astro",
        "astro.md",
        include_str!("../assets/review_rules/rule_docs/astro.md"),
    ),
    (
        "**/*.{ts,js,tsx,jsx}",
        "ts_js_tsx_jsx.md",
        include_str!("../assets/review_rules/rule_docs/ts_js_tsx_jsx.md"),
    ),
    (
        "**/*.{kt}",
        "kotlin.md",
        include_str!("../assets/review_rules/rule_docs/kotlin.md"),
    ),
    (
        "**/*.rs",
        "rust.md",
        include_str!("../assets/review_rules/rule_docs/rust.md"),
    ),
    (
        "**/*.{cpp,cc,hpp}",
        "cpp.md",
        include_str!("../assets/review_rules/rule_docs/cpp.md"),
    ),
    (
        "**/*.c",
        "c.md",
        include_str!("../assets/review_rules/rule_docs/c.md"),
    ),
    (
        "**/*.{py,ipynb}",
        "python.md",
        include_str!("../assets/review_rules/rule_docs/python.md"),
    ),
    (
        "**/*.{php,phtml}",
        "php.md",
        include_str!("../assets/review_rules/rule_docs/php.md"),
    ),
    (
        "**/*.proto",
        "protobuf.md",
        include_str!("../assets/review_rules/rule_docs/protobuf.md"),
    ),
    (
        "**/*.po",
        "po.md",
        include_str!("../assets/review_rules/rule_docs/po.md"),
    ),
    (
        "**/*.pot",
        "pot.md",
        include_str!("../assets/review_rules/rule_docs/pot.md"),
    ),
    (
        "**/*.{graphql,gql}",
        "graphql.md",
        include_str!("../assets/review_rules/rule_docs/graphql.md"),
    ),
    (
        "**/*.prisma",
        "prisma.md",
        include_str!("../assets/review_rules/rule_docs/prisma.md"),
    ),
    (
        "**/*.jl",
        "julia.md",
        include_str!("../assets/review_rules/rule_docs/julia.md"),
    ),
    (
        "**/*.R",
        "r.md",
        include_str!("../assets/review_rules/rule_docs/r.md"),
    ),
    (
        "**/*.{tf,hcl,tfvars}",
        "terraform.md",
        include_str!("../assets/review_rules/rule_docs/terraform.md"),
    ),
    (
        "**/*.bicep",
        "bicep.md",
        include_str!("../assets/review_rules/rule_docs/bicep.md"),
    ),
    (
        "**/*.nix",
        "nix.md",
        include_str!("../assets/review_rules/rule_docs/nix.md"),
    ),
    (
        "**/*.{hs,lhs}",
        "haskell.md",
        include_str!("../assets/review_rules/rule_docs/haskell.md"),
    ),
    (
        "**/*.{nim,nims,nimble}",
        "nim.md",
        include_str!("../assets/review_rules/rule_docs/nim.md"),
    ),
    (
        "**/*.swift",
        "swift.md",
        include_str!("../assets/review_rules/rule_docs/swift.md"),
    ),
    (
        "**/*.elm",
        "elm.md",
        include_str!("../assets/review_rules/rule_docs/elm.md"),
    ),
    (
        "**/*.{jsonnet,libsonnet}",
        "jsonnet.md",
        include_str!("../assets/review_rules/rule_docs/jsonnet.md"),
    ),
    (
        "**/*.zig",
        "zig.md",
        include_str!("../assets/review_rules/rule_docs/zig.md"),
    ),
    (
        "**/*.thrift",
        "thrift.md",
        include_str!("../assets/review_rules/rule_docs/thrift.md"),
    ),
    (
        "**/*.capnp",
        "capnp.md",
        include_str!("../assets/review_rules/rule_docs/capnp.md"),
    ),
    (
        "**/*.{v,sv,vh}",
        "verilog.md",
        include_str!("../assets/review_rules/rule_docs/verilog.md"),
    ),
    (
        "**/*.{vhd,vhdl}",
        "vhdl.md",
        include_str!("../assets/review_rules/rule_docs/vhdl.md"),
    ),
    (
        "**/*.mm",
        "objc.md",
        include_str!("../assets/review_rules/rule_docs/objc.md"),
    ),
    (
        "**/*.m",
        "matlab.md",
        include_str!("../assets/review_rules/rule_docs/matlab.md"),
    ),
    (
        "**/*.sol",
        "solidity.md",
        include_str!("../assets/review_rules/rule_docs/solidity.md"),
    ),
    (
        "**/*.vy",
        "vyper.md",
        include_str!("../assets/review_rules/rule_docs/vyper.md"),
    ),
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedReviewRule {
    pub id: &'static str,
    pub pattern: &'static str,
    pub guidance: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddedRuleError {
    InvalidPath,
    InvalidPattern,
}

/// Resolve the first embedded rule matching a normalized repository path.
///
/// # Errors
///
/// Returns a closed error for an invalid path or embedded glob.
pub fn resolve_embedded_rule(path: &str) -> Result<EmbeddedReviewRule, EmbeddedRuleError> {
    if path.is_empty() || path.contains(['\0', '\r', '\n']) || path.starts_with('/') {
        return Err(EmbeddedRuleError::InvalidPath);
    }
    for &(pattern, id, guidance) in RULES {
        let matcher = Glob::new(pattern)
            .map_err(|_| EmbeddedRuleError::InvalidPattern)?
            .compile_matcher();
        if matcher.is_match(path) {
            return Ok(EmbeddedReviewRule {
                id,
                pattern,
                guidance,
            });
        }
    }
    Ok(EmbeddedReviewRule {
        id: DEFAULT_RULE_ID,
        pattern: "**/*",
        guidance: DEFAULT_RULE,
    })
}

pub fn embedded_rule_ids() -> impl Iterator<Item = &'static str> {
    RULES
        .iter()
        .map(|(_, id, _)| *id)
        .chain(std::iter::once(DEFAULT_RULE_ID))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_specific_rules_before_generic_fallback() {
        assert_eq!(resolve_embedded_rule("src/lib.rs").unwrap().id, "rust.md");
        assert_eq!(
            resolve_embedded_rule(".github/workflows/ci.yml")
                .unwrap()
                .id,
            "github_workflows.md"
        );
        assert_eq!(resolve_embedded_rule("LICENSE").unwrap().id, "default.md");
    }

    #[test]
    fn corpus_is_complete_and_nonempty() {
        let rules = embedded_rule_ids().collect::<Vec<_>>();
        assert_eq!(rules.len(), 50);
        assert!(
            RULES
                .iter()
                .all(|(_, _, guidance)| !guidance.trim().is_empty())
        );
        assert!(!DEFAULT_RULE.trim().is_empty());
    }
}
