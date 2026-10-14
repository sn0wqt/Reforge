"""Goal parser and keyword extraction utility.

Separates intent verbs/modifiers from domain entity targets so verbs like
'grant', 'set', 'add' or modifiers like 'unlimited' are not searched as candidate field names.
"""

import re

from reforge.config.domain_keywords import (
    DOMAIN_EXPANSION_GROUPS,
    GOAL_STOPWORDS,
    MAXIMUM_TIER_ENTITY_KEYWORDS,
    MUTATION_MAGNITUDE_ASSIGNMENT_ACTIONS,
    NAMED_TIER_CONTEXT_KEYWORDS,
    NAMED_TIER_ENTITY_KEYWORDS,
    singularize_entity_token,
)


def extract_entity_keywords(goal_prompt: str) -> list[str]:
    """Extract clean entity target keywords from a goal prompt.

    Example:
        'grant unlimited diamonds' -> ['diamonds', 'diamond']
    """
    if not goal_prompt:
        return []

    tokens = [token.casefold() for token in re.findall(r"\b\w+\b", goal_prompt)]
    entities: list[str] = []

    # Some ordinary modifiers are also legitimate product/tier names.  Keep
    # "max" only when the sentence itself supplies subscription/plan context;
    # "set max coins" must still treat it as an intent modifier.
    contextual_entities: set[int] = set()
    for index, token in enumerate(tokens):
        if token not in MAXIMUM_TIER_ENTITY_KEYWORDS:
            continue
        nearby = tokens[max(0, index - 2) : index] + tokens[index + 1 : index + 3]
        has_context = any(
            singularize_entity_token(item) in NAMED_TIER_CONTEXT_KEYWORDS for item in nearby
        )
        coordinated_tier = (
            index >= 2
            and tokens[index - 1] == "and"
            and tokens[index - 2] in NAMED_TIER_ENTITY_KEYWORDS
        )
        magnitude_assignment = any(
            item in MUTATION_MAGNITUDE_ASSIGNMENT_ACTIONS for item in tokens[:index]
        )
        if has_context and (not magnitude_assignment or coordinated_tier):
            contextual_entities.add(index)

    for index, token in enumerate(tokens):
        if len(token) <= 1:
            continue
        if token.isdecimal():
            continue
        if token in GOAL_STOPWORDS and index not in contextual_entities:
            continue
        entities.append(token)
        singular = singularize_entity_token(token)
        if singular != token and singular not in GOAL_STOPWORDS and singular not in entities:
            entities.append(singular)

    return list(dict.fromkeys(entities))


def expand_goal_terms(goal_prompt: str) -> list[str]:
    """Return direct entities plus centralized, deterministic domain aliases."""
    terms = extract_entity_keywords(goal_prompt)
    tokens = set(re.findall(r"\b\w+\b", goal_prompt.casefold()))
    for triggers, expansions, ambiguous_triggers in DOMAIN_EXPANSION_GROUPS:
        matched_triggers = tokens & triggers
        if matched_triggers and not matched_triggers <= ambiguous_triggers:
            terms.extend(sorted(expansions))
    return list(dict.fromkeys(terms))
