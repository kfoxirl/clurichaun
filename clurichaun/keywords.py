"""Aho-Corasick keyword index for rule prefiltering.

At ~40 built-in rules a per-rule ``any(anchor in text)`` loop is cheapest —
N calls to C-implemented substring search beat a Python automaton walk. But with
``--rule-pack gitleaks`` the ruleset is ~254 rules, and that loop was measured at
~10 ms per blob while only ~18 rules survive it. Past that scale one automaton
pass over the text, yielding every matched keyword at once, wins.

This is a pure-Python Aho-Corasick trie (no ``pyahocorasick`` dependency). It
maps each lowercase keyword to the rule ids that declared it, so one pass over a
blob returns the set of rules whose prefilter matched. Rules with no prefilter
always run and are tracked separately.

The index is only built when it pays for itself (see ``ACTIVATION_THRESHOLD``);
below that the caller keeps the plain loop, and both paths must select exactly
the same rules — there is a test pinning that equivalence.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

ACTIVATION_THRESHOLD = 80


@dataclass(slots=True)
class _Node:
    children: Dict[str, int] = field(default_factory=dict)
    fail: int = 0
    outputs: List[int] = field(default_factory=list)  # keyword ids ending here


class KeywordIndex:
    """Map keywords -> rule ids; one ``candidates(text)`` pass returns matches."""

    def __init__(self) -> None:
        self._nodes: List[_Node] = [_Node()]
        self._keyword_rules: List[Set[str]] = []
        self._always: Set[str] = set()  # rules with no prefilter
        self._built = False

    # ------------------------------------------------------------------ #
    # Build
    # ------------------------------------------------------------------ #

    @classmethod
    def build(cls, rules: Sequence["_RuleLike"]) -> "KeywordIndex":
        index = cls()
        keyword_to_rules: Dict[str, Set[str]] = {}
        for rule in rules:
            if not rule.prefilter:
                index._always.add(rule.rule_id)
                continue
            for word in rule.prefilter:
                keyword_to_rules.setdefault(word.lower(), set()).add(rule.rule_id)
        for word, rule_ids in keyword_to_rules.items():
            index._add(word, rule_ids)
        index._finalize()
        return index

    def _add(self, word: str, rule_ids: Set[str]) -> None:
        node = 0
        for char in word:
            child = self._nodes[node].children.get(char)
            if child is None:
                child = len(self._nodes)
                self._nodes.append(_Node())
                self._nodes[node].children[char] = child
            node = child
        keyword_id = len(self._keyword_rules)
        self._keyword_rules.append(set(rule_ids))
        self._nodes[node].outputs.append(keyword_id)

    def _finalize(self) -> None:
        """Compute failure links (BFS), standard Aho-Corasick construction."""
        queue: deque[int] = deque()
        root = self._nodes[0]
        for child in root.children.values():
            self._nodes[child].fail = 0
            queue.append(child)
        while queue:
            current = queue.popleft()
            node = self._nodes[current]
            for char, child in node.children.items():
                queue.append(child)
                fail = node.fail
                while fail and char not in self._nodes[fail].children:
                    fail = self._nodes[fail].fail
                target = self._nodes[fail].children.get(char, 0)
                self._nodes[child].fail = target if target != child else 0
                # Merge output links so a suffix keyword is not missed.
                self._nodes[child].outputs += self._nodes[self._nodes[child].fail].outputs
        self._built = True

    # ------------------------------------------------------------------ #
    # Query
    # ------------------------------------------------------------------ #

    def candidate_rules(self, text: str) -> Set[str]:
        """Rule ids whose prefilter matched, plus every always-on rule."""
        matched: Set[str] = set(self._always)
        node = 0
        nodes = self._nodes
        lowered = text.lower()
        for char in lowered:
            while node and char not in nodes[node].children:
                node = nodes[node].fail
            node = nodes[node].children.get(char, 0)
            if node and nodes[node].outputs:
                for keyword_id in nodes[node].outputs:
                    matched |= self._keyword_rules[keyword_id]
        return matched


class _RuleLike:  # pragma: no cover - structural typing marker
    rule_id: str
    prefilter: Tuple[str, ...]
