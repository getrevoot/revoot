use std::collections::BTreeMap;

use regex::Regex;
use serde_json::Value;

pub fn assert_valid(schema: &Value, instance: &Value, external_schemas: &BTreeMap<&str, Value>) {
    if let Err(error) = validate(schema, instance, schema, external_schemas, "$".to_owned()) {
        panic!("contract schema validation failed: {error}");
    }
}

fn validate(
    schema: &Value,
    instance: &Value,
    root: &Value,
    external_schemas: &BTreeMap<&str, Value>,
    path: String,
) -> Result<(), String> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let (referenced, referenced_root) = resolve_reference(reference, root, external_schemas)?;
        return validate(
            referenced,
            instance,
            referenced_root,
            external_schemas,
            path,
        );
    }
    if let Some(branches) = schema.get("oneOf").and_then(Value::as_array) {
        let matches = branches
            .iter()
            .filter(|branch| {
                validate(branch, instance, root, external_schemas, path.clone()).is_ok()
            })
            .count();
        if matches != 1 {
            return Err(format!("{path}: expected exactly one oneOf match"));
        }
    }
    if let Some(expected) = schema.get("const")
        && instance != expected
    {
        return Err(format!("{path}: const mismatch"));
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array)
        && !values.contains(instance)
    {
        return Err(format!("{path}: enum mismatch"));
    }
    if let Some(kind) = schema.get("type").and_then(Value::as_str) {
        validate_type(kind, schema, instance, root, external_schemas, &path)?;
    }
    Ok(())
}

fn validate_type(
    kind: &str,
    schema: &Value,
    instance: &Value,
    root: &Value,
    external_schemas: &BTreeMap<&str, Value>,
    path: &str,
) -> Result<(), String> {
    match kind {
        "object" => validate_object(schema, instance, root, external_schemas, path),
        "array" => validate_array(schema, instance, root, external_schemas, path),
        "string" => validate_string(schema, instance, path),
        "integer" => validate_integer(schema, instance, path),
        "boolean" if instance.is_boolean() => Ok(()),
        "boolean" => Err(format!("{path}: expected boolean")),
        _ => Err(format!("{path}: unsupported or mismatched type {kind}")),
    }
}

fn validate_object(
    schema: &Value,
    instance: &Value,
    root: &Value,
    external_schemas: &BTreeMap<&str, Value>,
    path: &str,
) -> Result<(), String> {
    let object = instance
        .as_object()
        .ok_or_else(|| format!("{path}: expected object"))?;
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for key in required {
            let key = key
                .as_str()
                .ok_or_else(|| format!("{path}: invalid required entry"))?;
            if !object.contains_key(key) {
                return Err(format!("{path}: missing required property {key}"));
            }
        }
    }
    if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
        for key in object.keys() {
            if !properties.contains_key(key) {
                return Err(format!("{path}: unexpected property {key}"));
            }
        }
    }
    for (key, value) in object {
        if let Some(property_schema) = properties.get(key) {
            validate(
                property_schema,
                value,
                root,
                external_schemas,
                format!("{path}.{key}"),
            )?;
        }
    }
    Ok(())
}

fn validate_array(
    schema: &Value,
    instance: &Value,
    root: &Value,
    external_schemas: &BTreeMap<&str, Value>,
    path: &str,
) -> Result<(), String> {
    let items = instance
        .as_array()
        .ok_or_else(|| format!("{path}: expected array"))?;
    check_bound(schema, "minItems", items.len(), true, path)?;
    check_bound(schema, "maxItems", items.len(), false, path)?;
    if schema.get("uniqueItems") == Some(&Value::Bool(true)) {
        for (index, item) in items.iter().enumerate() {
            if items[..index].contains(item) {
                return Err(format!("{path}: duplicate array item"));
            }
        }
    }
    if let Some(item_schema) = schema.get("items") {
        for (index, item) in items.iter().enumerate() {
            validate(
                item_schema,
                item,
                root,
                external_schemas,
                format!("{path}[{index}]"),
            )?;
        }
    }
    Ok(())
}

fn validate_string(schema: &Value, instance: &Value, path: &str) -> Result<(), String> {
    let text = instance
        .as_str()
        .ok_or_else(|| format!("{path}: expected string"))?;
    check_bound(schema, "minLength", text.chars().count(), true, path)?;
    check_bound(schema, "maxLength", text.chars().count(), false, path)?;
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        let regex = Regex::new(pattern).map_err(|_| format!("{path}: invalid schema pattern"))?;
        if !regex.is_match(text) {
            return Err(format!("{path}: pattern mismatch"));
        }
    }
    Ok(())
}

fn validate_integer(schema: &Value, instance: &Value, path: &str) -> Result<(), String> {
    let number = instance
        .as_u64()
        .ok_or_else(|| format!("{path}: expected non-negative integer"))?;
    if schema
        .get("minimum")
        .and_then(Value::as_u64)
        .is_some_and(|minimum| number < minimum)
    {
        return Err(format!("{path}: below minimum"));
    }
    if schema
        .get("maximum")
        .and_then(Value::as_u64)
        .is_some_and(|maximum| number > maximum)
    {
        return Err(format!("{path}: above maximum"));
    }
    Ok(())
}

fn check_bound(
    schema: &Value,
    keyword: &str,
    observed: usize,
    is_minimum: bool,
    path: &str,
) -> Result<(), String> {
    let Some(bound) = schema.get(keyword).and_then(Value::as_u64) else {
        return Ok(());
    };
    let observed = u64::try_from(observed).map_err(|_| format!("{path}: size overflow"))?;
    if (is_minimum && observed < bound) || (!is_minimum && observed > bound) {
        return Err(format!("{path}: violates {keyword}"));
    }
    Ok(())
}

fn resolve_reference<'a>(
    reference: &str,
    root: &'a Value,
    external_schemas: &'a BTreeMap<&str, Value>,
) -> Result<(&'a Value, &'a Value), String> {
    if let Some(pointer) = reference.strip_prefix('#') {
        return root
            .pointer(pointer)
            .map(|target| (target, root))
            .ok_or_else(|| "unresolved local schema reference".to_owned());
    }
    external_schemas
        .get(reference)
        .map(|target| (target, target))
        .ok_or_else(|| "unresolved external schema reference".to_owned())
}
