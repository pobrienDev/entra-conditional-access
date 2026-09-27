"""Tests for the plan guardrails.

Each rule gets a passing and a failing case built from a small plan factory
that mirrors the real ``terraform show -json`` shape (nested blocks as
one-element lists). One test runs the checker over a redacted plan captured
from the real tenant, so the factory cannot drift from reality unnoticed.
"""

import copy
import json
from pathlib import Path

import pytest

import check_plan
from check_plan import REPORT_ONLY, Settings, check

BREAKGLASS = "00000000-0000-0000-0000-00000000000b"
SETTINGS = Settings(breakglass_group_id=BREAKGLASS)
FIXTURES = Path(__file__).parent / "fixtures"


# --- factory ------------------------------------------------------------------

def policy(
    name="CA001-AllUsers-AllApps-RequireMFA",
    *,
    state=REPORT_ONLY,
    excluded_groups=(BREAKGLASS,),
    included_users=("All",),
    included_roles=(),
    included_applications=("All",),
    client_app_types=("all",),
    built_in_controls=("mfa",),
    operator="OR",
    sign_in_risk_levels=(),
    user_risk_levels=(),
    sign_in_frequency_interval=None,
):
    """The ``after`` value of one policy, shaped like the provider emits it."""
    session = []
    if sign_in_frequency_interval is not None:
        session = [{"sign_in_frequency_interval": sign_in_frequency_interval}]
    return {
        "display_name": name,
        "state": state,
        "conditions": [{
            "client_app_types": list(client_app_types),
            "sign_in_risk_levels": list(sign_in_risk_levels),
            "user_risk_levels": list(user_risk_levels),
            "applications": [{"included_applications": list(included_applications),
                              "included_user_actions": []}],
            "users": [{"included_users": list(included_users),
                       "included_roles": list(included_roles),
                       "excluded_groups": list(excluded_groups)}],
        }],
        "grant_controls": [{"operator": operator, "built_in_controls": list(built_in_controls)}],
        "session_controls": session,
    }


def change(actions, *, before=None, after=None, address="azuread_conditional_access_policy.x",
           type_=check_plan.CA_TYPE):
    return {"address": address, "type": type_,
            "change": {"actions": list(actions), "before": before, "after": after}}


def plan(*changes):
    return {"format_version": "1.2", "resource_changes": list(changes)}


def create(after, **kw):
    return change(["create"], after=after, **kw)


def noop(after, **kw):
    return change(["no-op"], before=copy.deepcopy(after), after=after, **kw)


def update(before, after, **kw):
    return change(["update"], before=before, after=after, **kw)


# --- compliant plans -----------------------------------------------------------

def test_compliant_create_passes():
    assert check(plan(create(policy())), SETTINGS) == []


def test_compliant_noop_passes():
    assert check(plan(noop(policy())), SETTINGS) == []


def test_enabling_an_existing_report_only_policy_is_allowed():
    before = policy()
    after = policy(state="enabled")
    assert check(plan(update(before, after)), SETTINGS) == []


def test_rolling_back_to_report_only_is_allowed():
    assert check(plan(update(policy(state="enabled"), policy())), SETTINGS) == []


def test_non_ca_resources_are_ignored():
    bad = {"display_name": "whatever", "ip": [{"ip_ranges": ["203.0.113.0/24"]}]}
    p = plan(change(["delete"], before=bad, type_="azuread_named_location",
                    address="azuread_named_location.office[0]"))
    assert check(p, SETTINGS) == []


def test_empty_plan_is_clean_but_warns(capsys):
    assert check(plan(), SETTINGS) == []
    assert "::warning::" in capsys.readouterr().out


def test_real_baseline_plan_passes():
    real = json.loads((FIXTURES / "baseline_noop.json").read_text())
    assert check(real, SETTINGS) == []
    names = [rc["change"]["after"]["display_name"] for rc in real["resource_changes"]
             if rc["type"] == check_plan.CA_TYPE]
    assert len(names) == 7, "fixture should hold the full seven-policy baseline"


# --- break-glass exclusion -----------------------------------------------------

def test_missing_breakglass_exclusion_fails():
    errors = check(plan(create(policy(excluded_groups=()))), SETTINGS)
    assert errors == ["CA001-AllUsers-AllApps-RequireMFA: must exclude the break-glass group"]


def test_wrong_group_excluded_fails():
    other = "00000000-0000-0000-0000-00000000000f"
    errors = check(plan(create(policy(excluded_groups=(other,)))), SETTINGS)
    assert any("break-glass" in e for e in errors)


def test_breakglass_rule_applies_to_unchanged_policies_too():
    """A policy adopted from the portal in a bad state must still fail."""
    errors = check(plan(noop(policy(excluded_groups=()))), SETTINGS)
    assert any("break-glass" in e for e in errors)


def test_breakglass_exclusion_missing_from_after_is_not_assumed_present():
    """If Terraform cannot know the value yet (after_unknown), fail closed."""
    after = policy()
    del after["conditions"][0]["users"][0]["excluded_groups"]
    errors = check(plan(create(after)), SETTINGS)
    assert any("break-glass" in e for e in errors)


# --- report-only on create -----------------------------------------------------

def test_creating_an_enabled_policy_fails():
    errors = check(plan(create(policy(state="enabled"))), SETTINGS)
    assert errors == [
        "CA001-AllUsers-AllApps-RequireMFA: new policies must be created in report-only "
        f"({REPORT_ONLY}), not 'enabled'"
    ]


def test_creating_a_disabled_policy_fails():
    errors = check(plan(create(policy(state="disabled"))), SETTINGS)
    assert any("report-only" in e for e in errors)


# --- naming --------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "Require MFA",                   # free text
    "CA1-AllUsers-AllApps-MFA",      # number not three digits
    "CA001-AllUsers-RequireMFA",     # only three segments
    "CA001-All Users-AllApps-MFA",   # space
    "ca001-AllUsers-AllApps-MFA",    # lowercase prefix
])
def test_bad_names_fail(bad):
    errors = check(plan(create(policy(bad))), SETTINGS)
    assert f"{bad}: name must follow CA###-Who-What-Control" in errors


def test_duplicate_policy_number_fails():
    a = policy("CA001-AllUsers-AllApps-RequireMFA")
    b = policy("CA001-Admins-AllApps-Block", built_in_controls=("mfa",))
    errors = check(plan(noop(a, address="a.a"), create(b, address="b.b")), SETTINGS)
    assert errors == ["CA001-Admins-AllApps-Block: number CA001 is already used by "
                      "CA001-AllUsers-AllApps-RequireMFA"]


# --- deletion, replacement, disabling ------------------------------------------

def test_delete_is_blocked_by_default():
    errors = check(plan(change(["delete"], before=policy())), SETTINGS)
    assert errors == ["CA001-AllUsers-AllApps-RequireMFA: would be deleted; "
                      "removing a policy is blocked unless ALLOW_CA_DELETE=true"]


def test_delete_is_allowed_with_override():
    allowed = Settings(breakglass_group_id=BREAKGLASS, allow_delete=True)
    assert check(plan(change(["delete"], before=policy())), allowed) == []


def test_replace_is_blocked_by_default_and_new_copy_still_checked():
    errors = check(plan(change(["delete", "create"], before=policy(), after=policy(state="enabled"))),
                   SETTINGS)
    assert any("would be replaced" in e for e in errors)
    assert any("report-only" in e for e in errors)


def test_disabling_an_enabled_policy_is_blocked():
    errors = check(plan(update(policy(state="enabled"), policy(state="disabled"))), SETTINGS)
    assert errors == ["CA001-AllUsers-AllApps-RequireMFA: disabling a policy removes its "
                      "protection; blocked unless ALLOW_CA_DELETE=true"]


def test_disabling_is_allowed_with_override():
    allowed = Settings(breakglass_group_id=BREAKGLASS, allow_delete=True)
    assert check(plan(update(policy(state="enabled"), policy(state="disabled"))), allowed) == []


# --- all users, all apps, block ------------------------------------------------

def test_block_everyone_everywhere_fails():
    p = policy("CA009-AllUsers-AllApps-Block", built_in_controls=("block",))
    errors = check(plan(create(p)), SETTINGS)
    assert errors == ["CA009-AllUsers-AllApps-Block: blocks all users on all apps for "
                      "interactive clients; that would lock out every administrator"]


def test_block_via_browser_only_still_fails():
    p = policy("CA009-AllUsers-AllApps-Block", built_in_controls=("block",),
               client_app_types=("browser",))
    assert any("lock out" in e for e in check(plan(create(p)), SETTINGS))


def test_legacy_auth_block_is_fine():
    """CA003 is All users + All apps + Block, but only for legacy clients."""
    p = policy("CA003-AllUsers-LegacyAuth-Block", built_in_controls=("block",),
               client_app_types=("exchangeActiveSync", "other"))
    assert check(plan(create(p)), SETTINGS) == []


def test_block_scoped_to_roles_is_fine():
    p = policy("CA009-Guests-AllApps-Block", built_in_controls=("block",),
               included_users=(), included_roles=("00000000-0000-0000-0000-000000000009",))
    assert check(plan(create(p)), SETTINGS) == []


# --- risk policies need sign-in frequency every time ---------------------------

@pytest.mark.parametrize("kw", [
    {"sign_in_risk_levels": ("medium", "high")},
    {"user_risk_levels": ("high",)},
])
def test_risk_policy_without_every_time_fails(kw):
    p = policy("CA005-AllUsers-SignInRisk-MFA", **kw)
    errors = check(plan(create(p)), SETTINGS)
    assert errors == ["CA005-AllUsers-SignInRisk-MFA: risk-based policies must set sign-in "
                      "frequency to every time, or an existing session carries the risk through"]


def test_risk_policy_with_every_time_passes():
    p = policy("CA005-AllUsers-SignInRisk-MFA", sign_in_risk_levels=("medium", "high"),
               sign_in_frequency_interval="everyTime")
    assert check(plan(create(p)), SETTINGS) == []


def test_risk_policy_with_timed_frequency_fails():
    p = policy("CA005-AllUsers-SignInRisk-MFA", sign_in_risk_levels=("high",),
               sign_in_frequency_interval="timeBased")
    assert any("every time" in e for e in check(plan(create(p)), SETTINGS))


# --- several problems at once are all reported --------------------------------

def test_all_problems_reported_together():
    p = policy("bad name", state="enabled", excluded_groups=())
    errors = check(plan(create(p)), SETTINGS)
    assert len(errors) == 3
    assert {e.split(": ", 1)[1][:12] for e in errors} == {"new policies", "name must fo", "must exclude"}


# --- settings and CLI ----------------------------------------------------------

def test_settings_require_breakglass_id():
    with pytest.raises(SystemExit) as exc:
        Settings.from_env({})
    assert "BREAKGLASS_GROUP_ID" in str(exc.value)


def test_settings_parse_override():
    assert Settings.from_env({"BREAKGLASS_GROUP_ID": BREAKGLASS, "ALLOW_CA_DELETE": "TRUE"}).allow_delete
    assert not Settings.from_env({"BREAKGLASS_GROUP_ID": BREAKGLASS, "ALLOW_CA_DELETE": "yes"}).allow_delete


def test_main_exit_codes_and_annotations(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BREAKGLASS_GROUP_ID", BREAKGLASS)
    monkeypatch.delenv("ALLOW_CA_DELETE", raising=False)

    good = tmp_path / "good.json"
    good.write_text(json.dumps(plan(create(policy()))))
    assert check_plan.main(["check_plan.py", str(good)]) == 0

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(plan(create(policy(excluded_groups=())))))
    assert check_plan.main(["check_plan.py", str(bad)]) == 1
    out = capsys.readouterr().out
    assert "::error::CA001-AllUsers-AllApps-RequireMFA: must exclude the break-glass group" in out


def test_main_usage():
    assert check_plan.main(["check_plan.py"]) == 2
