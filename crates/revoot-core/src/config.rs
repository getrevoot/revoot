//! Pure requested/effective configuration resolution.
//!
//! Parsing files, reading environment variables, loading secrets, and choosing
//! product-specific schema fields belong outside this module. Callers provide a
//! closed schema, bounded non-secret values, assignments with redaction-safe
//! provenance, and optional administrator policy constraints.

use std::{borrow::Borrow, collections::BTreeMap, fmt};

use serde::Serialize;

const MAX_KEY_BYTES: usize = 128;
const MAX_PROVENANCE_BYTES: usize = 256;

/// A syntactically safe configuration key. Membership in a schema is checked
/// separately so a well-formed but unknown key is still rejected.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ConfigKey(String);

impl ConfigKey {
    /// Construct a dotted, lowercase ASCII key.
    ///
    /// Segments must start with a lowercase letter and may otherwise contain
    /// lowercase letters, digits, or underscores.
    ///
    /// # Errors
    ///
    /// Rejects empty or overlong keys and keys outside the documented grammar.
    pub fn new(value: impl Into<String>) -> Result<Self, ConfigKeyError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ConfigKeyError::Empty);
        }
        if value.len() > MAX_KEY_BYTES {
            return Err(ConfigKeyError::TooLong);
        }
        if !value.split('.').all(valid_key_segment) {
            return Err(ConfigKeyError::InvalidSyntax);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for ConfigKey {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ConfigKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

fn valid_key_segment(segment: &str) -> bool {
    let mut bytes = segment.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Reason a key could not be represented safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConfigKeyError {
    Empty,
    TooLong,
    InvalidSyntax,
}

/// Closed, non-secret configuration value representation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum ConfigValue {
    Bool(bool),
    Unsigned(u64),
    String(String),
    StringList(Vec<String>),
}

impl ConfigValue {
    #[must_use]
    pub const fn kind(&self) -> ConfigValueKind {
        match self {
            Self::Bool(_) => ConfigValueKind::Bool,
            Self::Unsigned(_) => ConfigValueKind::Unsigned,
            Self::String(_) => ConfigValueKind::String,
            Self::StringList(_) => ConfigValueKind::StringList,
        }
    }
}

/// Stable configuration value kind.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ConfigValueKind {
    Bool,
    Unsigned,
    String,
    StringList,
}

/// Requested-configuration precedence, from lowest to highest.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    CompiledDefault,
    BaseRepository,
    TrustedLocal,
    AllowedCiVariable,
    CommandLine,
}

/// Redaction-safe origin of one requested value.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceProvenance {
    source: ConfigSource,
    label: String,
}

impl SourceProvenance {
    #[must_use]
    pub fn new(source: ConfigSource, label: impl Into<String>) -> Self {
        Self {
            source,
            label: label.into(),
        }
    }

    fn compiled_default() -> Self {
        Self::new(ConfigSource::CompiledDefault, "compiled-default")
    }

    #[must_use]
    pub const fn source(&self) -> ConfigSource {
        self.source
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// Which requested-configuration sources may assign a field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AssignmentScope {
    /// Base-SHA repository preferences and every trusted higher-precedence layer.
    RepositoryAndTrusted,
    /// Trusted local, allowed CI, and command-line sources only.
    TrustedOnly,
    /// A fixed product invariant that cannot be assigned externally.
    CompiledDefaultOnly,
}

impl AssignmentScope {
    const fn permits(self, source: ConfigSource) -> bool {
        match (self, source) {
            (_, ConfigSource::CompiledDefault)
            | (Self::CompiledDefaultOnly, _)
            | (Self::TrustedOnly, ConfigSource::BaseRepository) => false,
            (Self::RepositoryAndTrusted | Self::TrustedOnly, _) => true,
        }
    }
}

/// Product-level value validity. These constraints are part of the schema and
/// cannot be loosened by administrator policy.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ValueConstraint {
    Any,
    UnsignedRange {
        min: u64,
        max: u64,
    },
    String {
        allow_empty: bool,
        max_bytes: usize,
    },
    StringList {
        max_items: usize,
        allow_empty_items: bool,
        max_item_bytes: usize,
    },
}

/// One member of the closed configuration schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigField {
    key: ConfigKey,
    default: ConfigValue,
    assignment_scope: AssignmentScope,
    value_constraint: ValueConstraint,
}

impl ConfigField {
    #[must_use]
    pub fn new(
        key: ConfigKey,
        default: ConfigValue,
        assignment_scope: AssignmentScope,
        value_constraint: ValueConstraint,
    ) -> Self {
        Self {
            key,
            default,
            assignment_scope,
            value_constraint,
        }
    }

    #[must_use]
    pub const fn key(&self) -> &ConfigKey {
        &self.key
    }

    #[must_use]
    pub const fn default(&self) -> &ConfigValue {
        &self.default
    }

    #[must_use]
    pub const fn assignment_scope(&self) -> AssignmentScope {
        self.assignment_scope
    }

    #[must_use]
    pub const fn value_constraint(&self) -> &ValueConstraint {
        &self.value_constraint
    }
}

/// Closed, validated configuration schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationSchema {
    fields: BTreeMap<ConfigKey, ConfigField>,
}

impl ConfigurationSchema {
    /// Validate and construct a closed schema.
    ///
    /// # Errors
    ///
    /// Rejects duplicate keys, constraint/value kind mismatches, malformed
    /// constraints, and defaults that violate their product constraints.
    pub fn try_new(
        fields: impl IntoIterator<Item = ConfigField>,
    ) -> Result<Self, ConfigurationError> {
        let mut fields: Vec<_> = fields.into_iter().collect();
        fields.sort_by(|left, right| left.key.cmp(&right.key));
        let mut validated = BTreeMap::new();
        for field in fields {
            if validated.contains_key(&field.key) {
                return Err(ConfigurationError::DuplicateSchemaField {
                    key: field.key.clone(),
                });
            }
            validate_value_constraint(&field)?;
            validate_field_value(&field, &field.default)?;
            validated.insert(field.key.clone(), field);
        }
        Ok(Self { fields: validated })
    }

    #[must_use]
    pub fn field(&self, key: &str) -> Option<&ConfigField> {
        self.fields.get(key)
    }

    #[must_use]
    pub fn fields(&self) -> impl ExactSizeIterator<Item = &ConfigField> {
        self.fields.values()
    }

    /// Resolve source precedence and then apply non-bypassable policy.
    ///
    /// # Errors
    ///
    /// Rejects unknown keys, duplicate assignments or policy rules, forbidden
    /// sources, invalid values/provenance, invalid policy constraints, and
    /// requested values outside an administrator allowlist.
    pub fn resolve(
        &self,
        assignments: impl IntoIterator<Item = ConfigAssignment>,
        policy_rules: impl IntoIterator<Item = PolicyRule>,
    ) -> Result<ConfigurationResolution, ConfigurationError> {
        let assignments = self.validate_assignments(assignments)?;
        let policy_rules = self.validate_policy(policy_rules)?;
        let mut requested_values = BTreeMap::new();
        let mut effective_values = BTreeMap::new();
        let mut explain = Vec::with_capacity(self.fields.len());

        for (key, field) in &self.fields {
            let mut candidates = vec![ConfigCandidate {
                value: field.default.clone(),
                provenance: SourceProvenance::compiled_default(),
            }];
            candidates.extend(
                assignments
                    .iter()
                    .filter(|assignment| assignment.key == *key)
                    .map(ConfigCandidate::from),
            );
            candidates.sort_by_key(|candidate| candidate.provenance.source);
            let mut requested = ResolvedValue {
                value: field.default.clone(),
                provenance: SourceProvenance::compiled_default(),
            };
            for candidate in &candidates {
                requested = ResolvedValue {
                    value: candidate.value.clone(),
                    provenance: candidate.provenance.clone(),
                };
            }
            let policy = policy_rules.get(key);
            let effective = apply_policy(field, &requested.value, policy)?;
            let policy_explanation =
                policy.map_or_else(PolicyExplanation::unconstrained, |rule| PolicyExplanation {
                    constraint: rule.constraint.clone(),
                    provenance: Some(rule.provenance.clone()),
                });
            explain.push(ConfigExplainRecord {
                key: key.clone(),
                candidates,
                requested: requested.clone(),
                policy: policy_explanation,
                constrained: requested.value != effective,
                effective: effective.clone(),
            });
            requested_values.insert(key.clone(), requested);
            effective_values.insert(key.clone(), effective);
        }

        Ok(ConfigurationResolution {
            requested: RequestedConfiguration {
                values: requested_values,
            },
            effective: EffectiveConfiguration {
                values: effective_values,
            },
            explain,
        })
    }

    fn validate_assignments(
        &self,
        assignments: impl IntoIterator<Item = ConfigAssignment>,
    ) -> Result<Vec<ConfigAssignment>, ConfigurationError> {
        let mut assignments: Vec<_> = assignments.into_iter().collect();
        assignments.sort_by(|left, right| {
            (&left.key, &left.provenance, &left.value).cmp(&(
                &right.key,
                &right.provenance,
                &right.value,
            ))
        });
        let mut previous: Option<(&ConfigKey, ConfigSource)> = None;
        for assignment in &assignments {
            let Some(field) = self.fields.get(&assignment.key) else {
                return Err(ConfigurationError::UnknownAssignmentKey {
                    key: assignment.key.clone(),
                });
            };
            validate_provenance(&assignment.key, &assignment.provenance)?;
            if assignment.provenance.source == ConfigSource::CompiledDefault {
                return Err(ConfigurationError::CompiledDefaultAssignment {
                    key: assignment.key.clone(),
                });
            }
            if !field.assignment_scope.permits(assignment.provenance.source) {
                return Err(ConfigurationError::AssignmentSourceForbidden {
                    key: assignment.key.clone(),
                    source: assignment.provenance.source,
                });
            }
            validate_field_value(field, &assignment.value)?;
            if previous == Some((&assignment.key, assignment.provenance.source)) {
                return Err(ConfigurationError::DuplicateSourceAssignment {
                    key: assignment.key.clone(),
                    source: assignment.provenance.source,
                });
            }
            previous = Some((&assignment.key, assignment.provenance.source));
        }
        Ok(assignments)
    }

    fn validate_policy(
        &self,
        policy_rules: impl IntoIterator<Item = PolicyRule>,
    ) -> Result<BTreeMap<ConfigKey, PolicyRule>, ConfigurationError> {
        let mut rules: Vec<_> = policy_rules.into_iter().collect();
        rules.sort_by(|left, right| left.key.cmp(&right.key));
        let mut validated = BTreeMap::new();
        for mut rule in rules {
            let Some(field) = self.fields.get(&rule.key) else {
                return Err(ConfigurationError::UnknownPolicyKey {
                    key: rule.key.clone(),
                });
            };
            if validated.contains_key(&rule.key) {
                return Err(ConfigurationError::DuplicatePolicyRule {
                    key: rule.key.clone(),
                });
            }
            if !valid_provenance_label(&rule.provenance) {
                return Err(ConfigurationError::InvalidPolicyProvenance {
                    key: rule.key.clone(),
                });
            }
            if let PolicyConstraint::AllowedValues(values) = &mut rule.constraint {
                values.sort();
            }
            validate_policy_constraint(field, &rule.constraint)?;
            validated.insert(rule.key.clone(), rule);
        }
        Ok(validated)
    }
}

/// One source assignment before requested-precedence resolution.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConfigAssignment {
    key: ConfigKey,
    value: ConfigValue,
    provenance: SourceProvenance,
}

impl ConfigAssignment {
    #[must_use]
    pub fn new(key: ConfigKey, value: ConfigValue, provenance: SourceProvenance) -> Self {
        Self {
            key,
            value,
            provenance,
        }
    }

    #[must_use]
    pub const fn key(&self) -> &ConfigKey {
        &self.key
    }

    #[must_use]
    pub const fn value(&self) -> &ConfigValue {
        &self.value
    }

    #[must_use]
    pub const fn provenance(&self) -> &SourceProvenance {
        &self.provenance
    }
}

/// Administrator constraint applied after requested-source precedence.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum PolicyConstraint {
    Unconstrained,
    Force(ConfigValue),
    ClampUnsigned { min: u64, max: u64 },
    AllowedValues(Vec<ConfigValue>),
}

/// One administrator policy rule. `provenance` must be a redaction-safe label,
/// never policy contents or secret material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRule {
    key: ConfigKey,
    constraint: PolicyConstraint,
    provenance: String,
}

impl PolicyRule {
    #[must_use]
    pub fn new(
        key: ConfigKey,
        constraint: PolicyConstraint,
        provenance: impl Into<String>,
    ) -> Self {
        Self {
            key,
            constraint,
            provenance: provenance.into(),
        }
    }

    #[must_use]
    pub const fn key(&self) -> &ConfigKey {
        &self.key
    }

    #[must_use]
    pub const fn constraint(&self) -> &PolicyConstraint {
        &self.constraint
    }

    #[must_use]
    pub fn provenance(&self) -> &str {
        &self.provenance
    }
}

/// A value plus the source selected by requested precedence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedValue {
    value: ConfigValue,
    provenance: SourceProvenance,
}

impl ResolvedValue {
    #[must_use]
    pub const fn value(&self) -> &ConfigValue {
        &self.value
    }

    #[must_use]
    pub const fn provenance(&self) -> &SourceProvenance {
        &self.provenance
    }
}

/// Requested values after source precedence but before policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RequestedConfiguration {
    values: BTreeMap<ConfigKey, ResolvedValue>,
}

impl RequestedConfiguration {
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&ResolvedValue> {
        self.values.get(key)
    }

    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&ConfigKey, &ResolvedValue)> {
        self.values.iter()
    }
}

/// Effective values after non-bypassable policy constraints.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectiveConfiguration {
    values: BTreeMap<ConfigKey, ConfigValue>,
}

impl EffectiveConfiguration {
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&ConfigValue> {
        self.values.get(key)
    }

    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&ConfigKey, &ConfigValue)> {
        self.values.iter()
    }
}

/// One source candidate in deterministic precedence order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConfigCandidate {
    pub value: ConfigValue,
    pub provenance: SourceProvenance,
}

impl From<&ConfigAssignment> for ConfigCandidate {
    fn from(assignment: &ConfigAssignment) -> Self {
        Self {
            value: assignment.value.clone(),
            provenance: assignment.provenance.clone(),
        }
    }
}

/// Policy details retained for explain output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyExplanation {
    pub constraint: PolicyConstraint,
    pub provenance: Option<String>,
}

impl PolicyExplanation {
    fn unconstrained() -> Self {
        Self {
            constraint: PolicyConstraint::Unconstrained,
            provenance: None,
        }
    }
}

/// Deterministic explanation of one requested/effective field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConfigExplainRecord {
    pub key: ConfigKey,
    pub candidates: Vec<ConfigCandidate>,
    pub requested: ResolvedValue,
    pub policy: PolicyExplanation,
    pub constrained: bool,
    pub effective: ConfigValue,
}

/// Requested configuration, effective configuration, and stable explain rows.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConfigurationResolution {
    requested: RequestedConfiguration,
    effective: EffectiveConfiguration,
    explain: Vec<ConfigExplainRecord>,
}

impl ConfigurationResolution {
    #[must_use]
    pub const fn requested(&self) -> &RequestedConfiguration {
        &self.requested
    }

    #[must_use]
    pub const fn effective(&self) -> &EffectiveConfiguration {
        &self.effective
    }

    #[must_use]
    pub fn explain(&self) -> &[ConfigExplainRecord] {
        &self.explain
    }

    /// Serialize explain records using their stable field and collection order.
    ///
    /// # Errors
    ///
    /// Returns an error if a future explain value cannot be represented as JSON.
    pub fn canonical_explain_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&self.explain)
    }
}

/// Pure configuration resolution failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConfigurationError {
    DuplicateSchemaField {
        key: ConfigKey,
    },
    InvalidValueConstraint {
        key: ConfigKey,
        violation: ConstraintViolation,
    },
    UnknownAssignmentKey {
        key: ConfigKey,
    },
    InvalidAssignmentProvenance {
        key: ConfigKey,
        source: ConfigSource,
    },
    CompiledDefaultAssignment {
        key: ConfigKey,
    },
    AssignmentSourceForbidden {
        key: ConfigKey,
        source: ConfigSource,
    },
    DuplicateSourceAssignment {
        key: ConfigKey,
        source: ConfigSource,
    },
    ValueKindMismatch {
        key: ConfigKey,
        expected: ConfigValueKind,
        actual: ConfigValueKind,
    },
    ValueRejected {
        key: ConfigKey,
        violation: ValueViolation,
    },
    UnknownPolicyKey {
        key: ConfigKey,
    },
    DuplicatePolicyRule {
        key: ConfigKey,
    },
    InvalidPolicyProvenance {
        key: ConfigKey,
    },
    InvalidPolicyConstraint {
        key: ConfigKey,
        violation: ConstraintViolation,
    },
    PolicyDeniedRequestedValue {
        key: ConfigKey,
    },
}

/// Invalid schema or policy constraint definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConstraintViolation {
    KindMismatch,
    InvertedRange,
    ZeroByteLimit,
    EmptyAllowedValues,
    DuplicateAllowedValue,
    AllowedValueKindMismatch,
    AllowedValueRejectedBySchema,
    PolicyWouldViolateSchema,
    FixedFieldPolicy,
}

/// A value outside the product schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ValueViolation {
    BelowMinimum,
    AboveMaximum,
    EmptyString,
    StringTooLong,
    TooManyListItems,
    EmptyListItem,
    ListItemTooLong,
}

fn validate_value_constraint(field: &ConfigField) -> Result<(), ConfigurationError> {
    let valid = match (&field.value_constraint, field.default.kind()) {
        (ValueConstraint::Any, _) => Ok(()),
        (ValueConstraint::UnsignedRange { min, max }, ConfigValueKind::Unsigned) => {
            if min <= max {
                Ok(())
            } else {
                Err(ConstraintViolation::InvertedRange)
            }
        }
        (ValueConstraint::String { max_bytes, .. }, ConfigValueKind::String)
        | (
            ValueConstraint::StringList {
                max_item_bytes: max_bytes,
                ..
            },
            ConfigValueKind::StringList,
        ) => {
            if *max_bytes == 0 {
                Err(ConstraintViolation::ZeroByteLimit)
            } else {
                Ok(())
            }
        }
        _ => Err(ConstraintViolation::KindMismatch),
    };
    valid.map_err(|violation| ConfigurationError::InvalidValueConstraint {
        key: field.key.clone(),
        violation,
    })
}

fn validate_field_value(
    field: &ConfigField,
    value: &ConfigValue,
) -> Result<(), ConfigurationError> {
    if value.kind() != field.default.kind() {
        return Err(ConfigurationError::ValueKindMismatch {
            key: field.key.clone(),
            expected: field.default.kind(),
            actual: value.kind(),
        });
    }
    validate_value(&field.value_constraint, value).map_err(|violation| {
        ConfigurationError::ValueRejected {
            key: field.key.clone(),
            violation,
        }
    })
}

fn validate_value(constraint: &ValueConstraint, value: &ConfigValue) -> Result<(), ValueViolation> {
    match (constraint, value) {
        (ValueConstraint::UnsignedRange { min, .. }, ConfigValue::Unsigned(value))
            if value < min =>
        {
            Err(ValueViolation::BelowMinimum)
        }
        (ValueConstraint::UnsignedRange { max, .. }, ConfigValue::Unsigned(value))
            if value > max =>
        {
            Err(ValueViolation::AboveMaximum)
        }
        (
            ValueConstraint::String {
                allow_empty: false, ..
            },
            ConfigValue::String(value),
        ) if value.is_empty() => Err(ValueViolation::EmptyString),
        (ValueConstraint::String { max_bytes, .. }, ConfigValue::String(value))
            if value.len() > *max_bytes =>
        {
            Err(ValueViolation::StringTooLong)
        }
        (ValueConstraint::StringList { max_items, .. }, ConfigValue::StringList(values))
            if values.len() > *max_items =>
        {
            Err(ValueViolation::TooManyListItems)
        }
        (
            ValueConstraint::StringList {
                allow_empty_items: false,
                ..
            },
            ConfigValue::StringList(values),
        ) if values.iter().any(String::is_empty) => Err(ValueViolation::EmptyListItem),
        (ValueConstraint::StringList { max_item_bytes, .. }, ConfigValue::StringList(values))
            if values.iter().any(|value| value.len() > *max_item_bytes) =>
        {
            Err(ValueViolation::ListItemTooLong)
        }
        (ValueConstraint::Any, _)
        | (ValueConstraint::UnsignedRange { .. }, ConfigValue::Unsigned(_))
        | (ValueConstraint::String { .. }, ConfigValue::String(_))
        | (ValueConstraint::StringList { .. }, ConfigValue::StringList(_)) => Ok(()),
        _ => unreachable!("constraint kind validated against field default"),
    }
}

fn validate_provenance(
    key: &ConfigKey,
    provenance: &SourceProvenance,
) -> Result<(), ConfigurationError> {
    if valid_provenance_label(&provenance.label) {
        Ok(())
    } else {
        Err(ConfigurationError::InvalidAssignmentProvenance {
            key: key.clone(),
            source: provenance.source,
        })
    }
}

fn valid_provenance_label(label: &str) -> bool {
    !label.trim().is_empty()
        && label.len() <= MAX_PROVENANCE_BYTES
        && !label.chars().any(char::is_control)
}

fn validate_policy_constraint(
    field: &ConfigField,
    constraint: &PolicyConstraint,
) -> Result<(), ConfigurationError> {
    let invalid = |violation| ConfigurationError::InvalidPolicyConstraint {
        key: field.key.clone(),
        violation,
    };
    if field.assignment_scope == AssignmentScope::CompiledDefaultOnly
        && *constraint != PolicyConstraint::Unconstrained
    {
        return Err(invalid(ConstraintViolation::FixedFieldPolicy));
    }
    match constraint {
        PolicyConstraint::Unconstrained => Ok(()),
        PolicyConstraint::Force(value) => {
            if value.kind() != field.default.kind() {
                return Err(invalid(ConstraintViolation::KindMismatch));
            }
            validate_field_value(field, value)
                .map_err(|_| invalid(ConstraintViolation::PolicyWouldViolateSchema))
        }
        PolicyConstraint::ClampUnsigned { min, max } => {
            if field.default.kind() != ConfigValueKind::Unsigned {
                return Err(invalid(ConstraintViolation::KindMismatch));
            }
            if min > max {
                return Err(invalid(ConstraintViolation::InvertedRange));
            }
            for endpoint in [*min, *max] {
                if validate_field_value(field, &ConfigValue::Unsigned(endpoint)).is_err() {
                    return Err(invalid(ConstraintViolation::PolicyWouldViolateSchema));
                }
            }
            Ok(())
        }
        PolicyConstraint::AllowedValues(values) => {
            if values.is_empty() {
                return Err(invalid(ConstraintViolation::EmptyAllowedValues));
            }
            if values.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(invalid(ConstraintViolation::DuplicateAllowedValue));
            }
            for value in values {
                if value.kind() != field.default.kind() {
                    return Err(invalid(ConstraintViolation::AllowedValueKindMismatch));
                }
                if validate_field_value(field, value).is_err() {
                    return Err(invalid(ConstraintViolation::AllowedValueRejectedBySchema));
                }
            }
            Ok(())
        }
    }
}

fn apply_policy(
    field: &ConfigField,
    requested: &ConfigValue,
    policy: Option<&PolicyRule>,
) -> Result<ConfigValue, ConfigurationError> {
    let Some(policy) = policy else {
        return Ok(requested.clone());
    };
    match &policy.constraint {
        PolicyConstraint::Unconstrained => Ok(requested.clone()),
        PolicyConstraint::Force(value) => Ok(value.clone()),
        PolicyConstraint::ClampUnsigned { min, max } => {
            let ConfigValue::Unsigned(value) = requested else {
                unreachable!("policy kind validated against schema")
            };
            Ok(ConfigValue::Unsigned((*value).clamp(*min, *max)))
        }
        PolicyConstraint::AllowedValues(values) => {
            if values.binary_search(requested).is_ok() {
                Ok(requested.clone())
            } else {
                Err(ConfigurationError::PolicyDeniedRequestedValue {
                    key: field.key.clone(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AssignmentScope, ConfigAssignment, ConfigField, ConfigKey, ConfigKeyError, ConfigSource,
        ConfigValue, ConfigurationError, ConfigurationSchema, ConstraintViolation,
        PolicyConstraint, PolicyRule, SourceProvenance, ValueConstraint, ValueViolation,
    };

    fn key(value: &str) -> ConfigKey {
        ConfigKey::new(value).unwrap()
    }

    fn schema() -> ConfigurationSchema {
        ConfigurationSchema::try_new([
            ConfigField::new(
                key("publication.enabled"),
                ConfigValue::Bool(false),
                AssignmentScope::TrustedOnly,
                ValueConstraint::Any,
            ),
            ConfigField::new(
                key("review.context_lines"),
                ConfigValue::Unsigned(20),
                AssignmentScope::RepositoryAndTrusted,
                ValueConstraint::UnsignedRange { min: 0, max: 500 },
            ),
            ConfigField::new(
                key("review.include_patterns"),
                ConfigValue::StringList(Vec::new()),
                AssignmentScope::RepositoryAndTrusted,
                ValueConstraint::StringList {
                    max_items: 8,
                    allow_empty_items: false,
                    max_item_bytes: 64,
                },
            ),
            ConfigField::new(
                key("review.model"),
                ConfigValue::String("review-model".to_owned()),
                AssignmentScope::TrustedOnly,
                ValueConstraint::String {
                    allow_empty: false,
                    max_bytes: 64,
                },
            ),
            ConfigField::new(
                key("review.repository_execution"),
                ConfigValue::Bool(false),
                AssignmentScope::CompiledDefaultOnly,
                ValueConstraint::Any,
            ),
        ])
        .unwrap()
    }

    fn assignment(key_name: &str, value: ConfigValue, source: ConfigSource) -> ConfigAssignment {
        ConfigAssignment::new(
            key(key_name),
            value,
            SourceProvenance::new(source, format!("{source:?}:{key_name}")),
        )
    }

    fn policy(key_name: &str, constraint: PolicyConstraint) -> PolicyRule {
        PolicyRule::new(key(key_name), constraint, "admin-policy:v1")
    }

    #[test]
    fn key_syntax_is_closed_and_bounded() {
        assert!(ConfigKey::new("review.context_lines").is_ok());
        assert_eq!(ConfigKey::new(""), Err(ConfigKeyError::Empty));
        assert_eq!(
            ConfigKey::new("Review.context"),
            Err(ConfigKeyError::InvalidSyntax)
        );
        assert_eq!(
            ConfigKey::new("review..context"),
            Err(ConfigKeyError::InvalidSyntax)
        );
        assert_eq!(
            ConfigKey::new(format!("a{}", "b".repeat(128))),
            Err(ConfigKeyError::TooLong)
        );
    }

    #[test]
    fn precedence_then_policy_produces_requested_effective_and_explain() {
        let assignments = [
            assignment(
                "review.context_lines",
                ConfigValue::Unsigned(30),
                ConfigSource::BaseRepository,
            ),
            assignment(
                "review.context_lines",
                ConfigValue::Unsigned(40),
                ConfigSource::TrustedLocal,
            ),
            assignment(
                "review.context_lines",
                ConfigValue::Unsigned(60),
                ConfigSource::AllowedCiVariable,
            ),
            assignment(
                "review.context_lines",
                ConfigValue::Unsigned(80),
                ConfigSource::CommandLine,
            ),
        ];
        let resolution = schema()
            .resolve(
                assignments,
                [policy(
                    "review.context_lines",
                    PolicyConstraint::ClampUnsigned { min: 5, max: 50 },
                )],
            )
            .unwrap();
        let requested = resolution.requested().get("review.context_lines").unwrap();
        assert_eq!(requested.value(), &ConfigValue::Unsigned(80));
        assert_eq!(requested.provenance().source(), ConfigSource::CommandLine);
        assert_eq!(
            resolution.effective().get("review.context_lines"),
            Some(&ConfigValue::Unsigned(50))
        );
        let row = resolution
            .explain()
            .iter()
            .find(|row| row.key.as_str() == "review.context_lines")
            .unwrap();
        assert!(row.constrained);
        assert_eq!(row.candidates.len(), 5);
        assert_eq!(
            row.candidates
                .iter()
                .map(|candidate| candidate.provenance.source())
                .collect::<Vec<_>>(),
            vec![
                ConfigSource::CompiledDefault,
                ConfigSource::BaseRepository,
                ConfigSource::TrustedLocal,
                ConfigSource::AllowedCiVariable,
                ConfigSource::CommandLine,
            ]
        );
    }

    #[test]
    fn resolution_and_explain_are_input_order_independent() {
        let low = assignment(
            "review.context_lines",
            ConfigValue::Unsigned(30),
            ConfigSource::BaseRepository,
        );
        let high = assignment(
            "review.context_lines",
            ConfigValue::Unsigned(40),
            ConfigSource::TrustedLocal,
        );
        let rule = policy(
            "review.context_lines",
            PolicyConstraint::ClampUnsigned { min: 10, max: 35 },
        );
        let left = schema()
            .resolve([low.clone(), high.clone()], [rule.clone()])
            .unwrap();
        let right = schema().resolve([high, low], [rule]).unwrap();
        assert_eq!(left, right);
        assert_eq!(
            left.canonical_explain_json().unwrap(),
            right.canonical_explain_json().unwrap()
        );
        assert!(
            left.explain()
                .windows(2)
                .all(|rows| rows[0].key < rows[1].key)
        );
    }

    #[test]
    fn defaults_are_explicit_in_requested_and_explain_output() {
        let resolution = schema()
            .resolve(Vec::<ConfigAssignment>::new(), Vec::<PolicyRule>::new())
            .unwrap();
        assert_eq!(resolution.requested().iter().len(), 5);
        assert_eq!(resolution.effective().iter().len(), 5);
        assert_eq!(resolution.explain().len(), 5);
        assert!(resolution.explain().iter().all(|row| {
            row.candidates.len() == 1
                && row.requested.provenance().source() == ConfigSource::CompiledDefault
                && !row.constrained
        }));
    }

    #[test]
    fn unknown_assignment_and_policy_keys_are_rejected() {
        let unknown = key("unknown.option");
        assert_eq!(
            schema().resolve(
                [ConfigAssignment::new(
                    unknown.clone(),
                    ConfigValue::Bool(true),
                    SourceProvenance::new(ConfigSource::TrustedLocal, "local"),
                )],
                Vec::<PolicyRule>::new(),
            ),
            Err(ConfigurationError::UnknownAssignmentKey {
                key: unknown.clone()
            })
        );
        assert_eq!(
            schema().resolve(
                Vec::<ConfigAssignment>::new(),
                [PolicyRule::new(
                    unknown.clone(),
                    PolicyConstraint::Unconstrained,
                    "admin",
                )],
            ),
            Err(ConfigurationError::UnknownPolicyKey { key: unknown })
        );
    }

    #[test]
    fn duplicate_assignments_from_one_source_are_rejected_even_if_identical() {
        let value = assignment(
            "review.context_lines",
            ConfigValue::Unsigned(25),
            ConfigSource::TrustedLocal,
        );
        assert_eq!(
            schema().resolve([value.clone(), value], Vec::<PolicyRule>::new()),
            Err(ConfigurationError::DuplicateSourceAssignment {
                key: key("review.context_lines"),
                source: ConfigSource::TrustedLocal,
            })
        );
    }

    #[test]
    fn repository_and_all_external_sources_respect_field_scope() {
        assert_eq!(
            schema().resolve(
                [assignment(
                    "review.model",
                    ConfigValue::String("other-model".to_owned()),
                    ConfigSource::BaseRepository,
                )],
                Vec::<PolicyRule>::new(),
            ),
            Err(ConfigurationError::AssignmentSourceForbidden {
                key: key("review.model"),
                source: ConfigSource::BaseRepository,
            })
        );
        assert_eq!(
            schema().resolve(
                [assignment(
                    "review.repository_execution",
                    ConfigValue::Bool(true),
                    ConfigSource::CommandLine,
                )],
                Vec::<PolicyRule>::new(),
            ),
            Err(ConfigurationError::AssignmentSourceForbidden {
                key: key("review.repository_execution"),
                source: ConfigSource::CommandLine,
            })
        );
    }

    #[test]
    fn caller_cannot_supply_or_spoof_the_compiled_default_layer() {
        assert_eq!(
            schema().resolve(
                [assignment(
                    "review.context_lines",
                    ConfigValue::Unsigned(25),
                    ConfigSource::CompiledDefault,
                )],
                Vec::<PolicyRule>::new(),
            ),
            Err(ConfigurationError::CompiledDefaultAssignment {
                key: key("review.context_lines")
            })
        );
    }

    #[test]
    fn value_types_and_product_bounds_are_enforced_before_precedence() {
        assert!(matches!(
            schema().resolve(
                [assignment(
                    "review.context_lines",
                    ConfigValue::String("20".to_owned()),
                    ConfigSource::TrustedLocal,
                )],
                Vec::<PolicyRule>::new(),
            ),
            Err(ConfigurationError::ValueKindMismatch { .. })
        ));
        assert_eq!(
            schema().resolve(
                [assignment(
                    "review.context_lines",
                    ConfigValue::Unsigned(501),
                    ConfigSource::TrustedLocal,
                )],
                Vec::<PolicyRule>::new(),
            ),
            Err(ConfigurationError::ValueRejected {
                key: key("review.context_lines"),
                violation: ValueViolation::AboveMaximum,
            })
        );
    }

    #[test]
    fn duplicate_schema_fields_and_policy_rules_are_rejected() {
        let field = ConfigField::new(
            key("review.context_lines"),
            ConfigValue::Unsigned(20),
            AssignmentScope::RepositoryAndTrusted,
            ValueConstraint::UnsignedRange { min: 0, max: 100 },
        );
        assert_eq!(
            ConfigurationSchema::try_new([field.clone(), field]),
            Err(ConfigurationError::DuplicateSchemaField {
                key: key("review.context_lines")
            })
        );
        let rule = policy("review.model", PolicyConstraint::Unconstrained);
        assert_eq!(
            schema().resolve(Vec::<ConfigAssignment>::new(), [rule.clone(), rule]),
            Err(ConfigurationError::DuplicatePolicyRule {
                key: key("review.model")
            })
        );
    }

    #[test]
    fn invalid_constraint_combinations_are_rejected() {
        let inverted = ConfigField::new(
            key("review.context_lines"),
            ConfigValue::Unsigned(20),
            AssignmentScope::RepositoryAndTrusted,
            ValueConstraint::UnsignedRange { min: 100, max: 10 },
        );
        assert_eq!(
            ConfigurationSchema::try_new([inverted]),
            Err(ConfigurationError::InvalidValueConstraint {
                key: key("review.context_lines"),
                violation: ConstraintViolation::InvertedRange,
            })
        );
        let rejected_default = ConfigField::new(
            key("review.context_lines"),
            ConfigValue::Unsigned(101),
            AssignmentScope::RepositoryAndTrusted,
            ValueConstraint::UnsignedRange { min: 0, max: 100 },
        );
        assert_eq!(
            ConfigurationSchema::try_new([rejected_default]),
            Err(ConfigurationError::ValueRejected {
                key: key("review.context_lines"),
                violation: ValueViolation::AboveMaximum,
            })
        );
        assert_eq!(
            schema().resolve(
                Vec::<ConfigAssignment>::new(),
                [policy(
                    "review.model",
                    PolicyConstraint::ClampUnsigned { min: 0, max: 1 },
                )],
            ),
            Err(ConfigurationError::InvalidPolicyConstraint {
                key: key("review.model"),
                violation: ConstraintViolation::KindMismatch,
            })
        );
        assert_eq!(
            schema().resolve(
                Vec::<ConfigAssignment>::new(),
                [policy(
                    "review.context_lines",
                    PolicyConstraint::ClampUnsigned { min: 0, max: 600 },
                )],
            ),
            Err(ConfigurationError::InvalidPolicyConstraint {
                key: key("review.context_lines"),
                violation: ConstraintViolation::PolicyWouldViolateSchema,
            })
        );
        assert_eq!(
            schema().resolve(
                Vec::<ConfigAssignment>::new(),
                [policy(
                    "review.repository_execution",
                    PolicyConstraint::Force(ConfigValue::Bool(true)),
                )],
            ),
            Err(ConfigurationError::InvalidPolicyConstraint {
                key: key("review.repository_execution"),
                violation: ConstraintViolation::FixedFieldPolicy,
            })
        );
    }

    #[test]
    fn allowed_values_are_sorted_unique_and_fail_closed() {
        let duplicate_policy = policy(
            "review.model",
            PolicyConstraint::AllowedValues(vec![
                ConfigValue::String("review-model".to_owned()),
                ConfigValue::String("review-model".to_owned()),
            ]),
        );
        assert!(matches!(
            schema().resolve(Vec::<ConfigAssignment>::new(), [duplicate_policy]),
            Err(ConfigurationError::InvalidPolicyConstraint {
                violation: ConstraintViolation::DuplicateAllowedValue,
                ..
            })
        ));

        let allowed_values = vec![
            ConfigValue::String("review-model".to_owned()),
            ConfigValue::String("high-accuracy".to_owned()),
        ];
        let canonical = schema()
            .resolve(
                Vec::<ConfigAssignment>::new(),
                [policy(
                    "review.model",
                    PolicyConstraint::AllowedValues(allowed_values.clone()),
                )],
            )
            .unwrap();
        assert_eq!(
            canonical
                .explain()
                .iter()
                .find(|row| row.key.as_str() == "review.model")
                .unwrap()
                .policy
                .constraint,
            PolicyConstraint::AllowedValues(vec![
                ConfigValue::String("high-accuracy".to_owned()),
                ConfigValue::String("review-model".to_owned()),
            ])
        );

        let denied = schema().resolve(
            [assignment(
                "review.model",
                ConfigValue::String("unapproved-model".to_owned()),
                ConfigSource::TrustedLocal,
            )],
            [policy(
                "review.model",
                PolicyConstraint::AllowedValues(allowed_values),
            )],
        );
        assert_eq!(
            denied,
            Err(ConfigurationError::PolicyDeniedRequestedValue {
                key: key("review.model")
            })
        );
    }

    #[test]
    fn force_policy_cannot_be_bypassed_by_the_highest_requested_source() {
        let resolution = schema()
            .resolve(
                [assignment(
                    "publication.enabled",
                    ConfigValue::Bool(true),
                    ConfigSource::CommandLine,
                )],
                [policy(
                    "publication.enabled",
                    PolicyConstraint::Force(ConfigValue::Bool(false)),
                )],
            )
            .unwrap();
        assert_eq!(
            resolution
                .requested()
                .get("publication.enabled")
                .unwrap()
                .value(),
            &ConfigValue::Bool(true)
        );
        assert_eq!(
            resolution.effective().get("publication.enabled"),
            Some(&ConfigValue::Bool(false))
        );
        let row = resolution
            .explain()
            .iter()
            .find(|row| row.key.as_str() == "publication.enabled")
            .unwrap();
        assert_eq!(row.policy.provenance.as_deref(), Some("admin-policy:v1"));
        assert!(row.constrained);
    }

    #[test]
    fn invalid_provenance_is_not_copied_into_explain() {
        let control_character = ConfigAssignment::new(
            key("review.context_lines"),
            ConfigValue::Unsigned(25),
            SourceProvenance::new(ConfigSource::TrustedLocal, "local\nsecret"),
        );
        assert_eq!(
            schema().resolve([control_character], Vec::<PolicyRule>::new()),
            Err(ConfigurationError::InvalidAssignmentProvenance {
                key: key("review.context_lines"),
                source: ConfigSource::TrustedLocal,
            })
        );
        assert_eq!(
            schema().resolve(
                Vec::<ConfigAssignment>::new(),
                [PolicyRule::new(
                    key("review.model"),
                    PolicyConstraint::Unconstrained,
                    "admin\nsecret",
                )],
            ),
            Err(ConfigurationError::InvalidPolicyProvenance {
                key: key("review.model")
            })
        );
    }
}
