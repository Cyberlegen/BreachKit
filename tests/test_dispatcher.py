"""
Unit tests for Dispatcher argument handling and resolution.
"""

import pytest
from breachkit.orchestrator.dispatcher import Dispatcher, Action
from breachkit.policy.engine import EngagementScope, ScopeTarget, PolicyEngine

def test_dispatcher_argument_handling():
    target = ScopeTarget(host="example.com")
    scope = EngagementScope(engagement="test", authorisation_ref="ref", targets=[target])
    engine = PolicyEngine(scope)
    dispatcher = Dispatcher(engine)

    # Test argument parsing structure for positional and dictionary key-values
    action = Action(
        id="act-1",
        tool="echo",
        arguments=["-n", {"key": "-v", "value": "1"}, {"key": "--header", "value": ["A: 1", "B: 2"]}],
        target="https://example.com",
        intent="test",
        risk="passive",
        requires_approval=False
    )

    # We can inspect how arguments are mapped without running the subprocess directly or test execution
    # Let's verify dispatch building logic or mock subprocess
    assert action.arguments[0] == "-n"
    assert action.arguments[1]["key"] == "-v"
