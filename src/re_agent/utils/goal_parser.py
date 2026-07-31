"""Goal parser and keyword extraction utility.

Separates intent verbs/modifiers from domain entity targets so verbs like
'grant', 'set', 'add' or modifiers like 'unlimited' are not searched as candidate field names.
"""

import re

from re_agent.config.domain_keywords import GOAL_STOPWORDS


def extract_entity_keywords(goal_prompt: str) -> list[str]:
    """Extract clean entity target keywords from a goal prompt.

    Example:
        'grant unlimited diamonds' -> ['diamonds', 'diamond']
    """
    if not goal_prompt:
        return []

    tokens = re.findall(r"\b\w+\b", goal_prompt.lower())
    entities: list[str] = []

    for token in tokens:
        if len(token) <= 2:
            continue
        if token in GOAL_STOPWORDS:
            continue
        entities.append(token)
        # Add a conservative English singular variant for search expansion.
        if (
            token.endswith("s")
            and len(token) > 3
            and not token.endswith(("ss", "us", "is", "ous"))
        ):
            if token.endswith("ies") and len(token) > 4:
                singular = token[:-3] + "y"
            elif token.endswith(("ches", "shes", "xes", "zes", "ses")):
                singular = token[:-2]
            else:
                singular = token[:-1]
            if singular not in GOAL_STOPWORDS and singular not in entities:
                entities.append(singular)

    return list(dict.fromkeys(entities))
