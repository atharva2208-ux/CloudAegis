"""CloudAegis must never change cloud infrastructure.

Two guards: the IAM policy we ask customers to grant contains only read
actions, and no collector source code calls a mutating boto3 operation.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from cloudaegis_engine.providers.aws.permissions import REQUIRED_ACTIONS

COLLECTORS = Path(__file__).resolve().parents[2] / "packages/security-engine/cloudaegis_engine/providers/aws/collectors"
READ_VERBS = ("Describe", "Get", "List")
MUTATING = re.compile(
    r"^(put|create|delete|update|modify|attach|detach|associate|disassociate|authorize|revoke|run|start|stop|"
    r"terminate|reboot|enable|disable|tag|untag|set|add|remove|replace|reset|restore|import|copy|upload|invoke|"
    r"publish|send|cancel|schedule|rotate|register|deregister)_"
)


@pytest.mark.parametrize("action", REQUIRED_ACTIONS)
def test_required_actions_are_read_only(action):
    service, _, name = action.partition(":")
    assert service and name
    assert name.startswith(READ_VERBS), f"{action} is not a read-only action"


def test_no_wildcard_actions():
    assert not any("*" in a for a in REQUIRED_ACTIONS)


def _called_methods(source: str) -> set[str]:
    return {node.func.attr for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}


@pytest.mark.parametrize("path", sorted(COLLECTORS.glob("*.py")), ids=lambda p: p.name)
def test_collectors_never_call_mutating_apis(path):
    offenders = sorted(m for m in _called_methods(path.read_text()) if MUTATING.match(m))
    assert not offenders, f"{path.name} calls mutating APIs: {offenders}"
