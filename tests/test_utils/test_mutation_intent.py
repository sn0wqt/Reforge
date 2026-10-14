from re_agent.utils.mutation_intent import (
    infer_primitive_replacement,
    primitive_literal_kind,
    replacement_matches_literal,
)


def test_application_neutral_numeric_intents() -> None:
    assert infer_primitive_replacement("grant unlimited glimmers", current_literal="3") == "999999999"
    assert infer_primitive_replacement("set warp charges to 12", type_name="System.Int32") == "12"
    assert infer_primitive_replacement("set temperature to 2.5", type_name="float") == "2.5"
    assert infer_primitive_replacement("disable retry count", type_name="int32_t") == "0"


def test_application_neutral_boolean_intents() -> None:
    assert infer_primitive_replacement("disable telemetry", current_literal="true") == "false"
    assert infer_primitive_replacement("unlock pro access", type_name="boolean") == "true"
    assert infer_primitive_replacement("inspect telemetry", current_literal="true") is None


def test_inference_fails_closed_for_unknown_or_incompatible_types() -> None:
    assert infer_primitive_replacement("enable profile", current_literal="null") is None
    assert infer_primitive_replacement("set profile", type_name="java.lang.String") is None
    assert infer_primitive_replacement("set retries", current_literal="3") is None
    assert primitive_literal_kind("1e3") == "float"
    assert replacement_matches_literal("false", "true")
    assert not replacement_matches_literal("true", "3")


def test_explicit_boolean_assignment_overrides_surrounding_action_words() -> None:
    assert infer_primitive_replacement("enable telemetry to 0", type_name="boolean") == "false"
    assert infer_primitive_replacement("disable telemetry to 1", type_name="boolean") == "true"
    assert infer_primitive_replacement("enable telemetry to 2", type_name="boolean") is None


def test_integer_mutations_respect_recovered_type_ranges() -> None:
    assert infer_primitive_replacement("grant unlimited retries", type_name="byte") == "127"
    assert infer_primitive_replacement("set retries to 127", type_name="byte") == "127"
    assert infer_primitive_replacement("set retries to 128", type_name="byte") is None
    assert infer_primitive_replacement("set retries to -1", type_name="uint32_t") is None


def test_float_literals_remain_valid_and_respect_recovered_range() -> None:
    assert infer_primitive_replacement("set ratio to 1e3", type_name="float") == "1e3"
    assert infer_primitive_replacement("set ratio to 1e40", type_name="float") is None
