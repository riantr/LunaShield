///|
/// Fixed predicate whitelist. Tree-sitter native predicates live in the query string.
///
/// `*_ignore_case` variants fold ASCII uppercase to lowercase on both sides
/// before comparing; non-ASCII characters are left untouched. This keeps the
/// comparison deterministic across targets and avoids locale-dependent rules.
#derive(Debug, Eq)
pub(all) enum PredicateKind {
  TextEquals
  TextNotEquals
  HasPrefix
  NotHasPrefix
  HasSuffix
  NotHasSuffix
  Contains
  NotContains
  TextEqualsIgnoreCase
  TextNotEqualsIgnoreCase
  HasPrefixIgnoreCase
  NotHasPrefixIgnoreCase
  HasSuffixIgnoreCase
  NotHasSuffixIgnoreCase
  ContainsIgnoreCase
  NotContainsIgnoreCase
}

///|
/// A single host-side predicate on a captured node's source text.
#derive(Debug, Eq, @json.ToJson)
pub(all) struct PredicateSpec {
  kind : PredicateKind
  capture : String
  value : String
}

///|
/// A SAST rule. `enabled` defaults to true when omitted in JSON.
#derive(Debug, Eq, @json.ToJson)
pub(all) struct Rule {
  id : String
  language : String
  severity : @core.Severity
  cwe : Array[Int32]
  owasp : Array[String]
  query : String
  predicates : Array[PredicateSpec]
  message : String
  enabled : Bool
}

///| Error with a JSON Pointer path and message, used by rules-validate.

///|
/// A `suberror` so parse/validate functions can `raise` it concisely.
pub suberror RuleError {
  RuleError(path~ : String, message~ : String)
}

///|
/// Parse a predicate kind from its lowercase JSON name.
pub fn predicate_kind_from_string(s : String) -> PredicateKind? {
  match s {
    "text_equals" => Some(TextEquals)
    "text_not_equals" => Some(TextNotEquals)
    "has_prefix" => Some(HasPrefix)
    "not_has_prefix" => Some(NotHasPrefix)
    "has_suffix" => Some(HasSuffix)
    "not_has_suffix" => Some(NotHasSuffix)
    "contains" => Some(Contains)
    "not_contains" => Some(NotContains)
    "text_equals_ignore_case" => Some(TextEqualsIgnoreCase)
    "text_not_equals_ignore_case" => Some(TextNotEqualsIgnoreCase)
    "has_prefix_ignore_case" => Some(HasPrefixIgnoreCase)
    "not_has_prefix_ignore_case" => Some(NotHasPrefixIgnoreCase)
    "has_suffix_ignore_case" => Some(HasSuffixIgnoreCase)
    "not_has_suffix_ignore_case" => Some(NotHasSuffixIgnoreCase)
    "contains_ignore_case" => Some(ContainsIgnoreCase)
    "not_contains_ignore_case" => Some(NotContainsIgnoreCase)
    _ => None
  }
}

///|
/// Stable lowercase name of a predicate kind (inverse of the parser).
pub fn predicate_kind_name(k : PredicateKind) -> String {
  match k {
    TextEquals => "text_equals"
    TextNotEquals => "text_not_equals"
    HasPrefix => "has_prefix"
    NotHasPrefix => "not_has_prefix"
    HasSuffix => "has_suffix"
    NotHasSuffix => "not_has_suffix"
    Contains => "contains"
    NotContains => "not_contains"
    TextEqualsIgnoreCase => "text_equals_ignore_case"
    TextNotEqualsIgnoreCase => "text_not_equals_ignore_case"
    HasPrefixIgnoreCase => "has_prefix_ignore_case"
    NotHasPrefixIgnoreCase => "not_has_prefix_ignore_case"
    HasSuffixIgnoreCase => "has_suffix_ignore_case"
    NotHasSuffixIgnoreCase => "not_has_suffix_ignore_case"
    ContainsIgnoreCase => "contains_ignore_case"
    NotContainsIgnoreCase => "not_contains_ignore_case"
  }
}

///|
/// All known predicate kind names, for `rules-validate` error messages.
pub fn predicate_kind_names() -> Array[String] {
  [
    "text_equals", "text_not_equals", "has_prefix", "not_has_prefix", "has_suffix",
    "not_has_suffix", "contains", "not_contains", "text_equals_ignore_case", "text_not_equals_ignore_case",
    "has_prefix_ignore_case", "not_has_prefix_ignore_case", "has_suffix_ignore_case",
    "not_has_suffix_ignore_case", "contains_ignore_case", "not_contains_ignore_case",
  ]
}

///|
/// Stable lowercase serialization for predicate kinds.
pub impl @json.ToJson for PredicateKind with fn to_json(self) -> @json.Json {
  @json.Json::string(predicate_kind_name(self))
}
