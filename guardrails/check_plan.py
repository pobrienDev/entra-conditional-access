#!/usr/bin/env python3
"""Policy-as-code guardrails for Conditional Access plans.

usage: python guardrails/check_plan.py plan.json

Reads the JSON form of a Terraform plan (``terraform show -json tfplan``) and
refuses changes that could lock administrators out of the tenant or silently
remove protection. Prints one ``::error::`` line per problem, which GitHub
renders as an annotation on the pull request, and exits 1. Exits 0 when clean.

Two kinds of rule:

* Change rules look at what the plan *does* (create, update, delete) and only
  apply to policies that are changing.
* Desired-state rules look at what every policy *will be* after apply, and
  apply to unchanged policies too. A policy that drifted into a bad shape in
  the portal and was then adopted into code still fails.

The script fails closed: a value Terraform cannot know until apply time is
treated as wrong, not as fine.

Environment:
  BREAKGLASS_GROUP_ID  required. Object ID of the group every policy must
                       exclude. Comes from CI configuration, never from the
                       repository, so a pull request cannot change it.
  ALLOW_CA_DELETE      "true" permits deleting, replacing or disabling a
                       policy for this one run. Removing protection should be
                       a deliberate, reviewed decision, not a side effect.

Standard library only, so CI needs nothing installed beyond Python.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Mapping

CA_TYPE = "azuread_conditional_access_policy"
REPORT_ONLY = "enabledForReportingButNotEnforced"
DISABLED = "disabled"

# CA###-Who-What-Control. The captured group is the number, used to catch
# two policies claiming the same one.
NAME_RULE = re.compile(r"^CA(\d{3})-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+$")

# Client app types an administrator uses to reach the portal. A block that
# covers any of these for all users on all apps locks out every admin. A
# block limited to legacy clients (exchangeActiveSync, other) does not.
INTERACTIVE_CLIENTS = frozenset({"all", "browser", "mobileAppsAndDesktopClients"})


@dataclass(frozen=True)
class Settings:
    breakglass_group_id: str
    allow_delete: bool = False

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "Settings":
        group_id = env.get("BREAKGLASS_GROUP_ID", "").strip()
        if not group_id:
            raise SystemExit(
                "::error::BREAKGLASS_GROUP_ID is not set; refusing to run "
                "without knowing which group every policy must exclude"
            )
        return cls(
            breakglass_group_id=group_id,
            allow_delete=env.get("ALLOW_CA_DELETE", "").strip().lower() == "true",
        )


def _first(block: Any) -> dict:
    """Terraform's JSON renders a nested block as a list; ours are max-one."""
    if isinstance(block, list) and block:
        return block[0] or {}
    return {}


def check(plan: Mapping[str, Any], settings: Settings) -> list[str]:
    """Return every problem found in the plan. Empty list means clean."""
    errors: list[str] = []
    numbers_seen: dict[str, str] = {}
    policies_checked = 0

    for rc in plan.get("resource_changes", []):
        if rc.get("type") != CA_TYPE:
            continue

        address = rc.get("address", "<unknown address>")
        change = rc.get("change") or {}
        actions = list(change.get("actions") or [])
        before = change.get("before") or {}
        after = change.get("after")

        # --- change rules ---------------------------------------------------
        if "delete" in actions:
            verb = "replaced" if "create" in actions else "deleted"
            if not settings.allow_delete:
                errors.append(
                    f"{before.get('display_name', address)}: would be {verb}; "
                    "removing a policy is blocked unless ALLOW_CA_DELETE=true"
                )
            if "create" not in actions:
                continue  # pure delete: nothing after apply to inspect

        if after is None:
            continue

        name = after.get("display_name") or address
        state = after.get("state")

        if "create" in actions and state != REPORT_ONLY:
            errors.append(
                f"{name}: new policies must be created in report-only "
                f"({REPORT_ONLY}), not {state!r}"
            )

        if (
            "update" in actions
            and state == DISABLED
            and before.get("state") != DISABLED
            and not settings.allow_delete
        ):
            errors.append(
                f"{name}: disabling a policy removes its protection; "
                "blocked unless ALLOW_CA_DELETE=true"
            )

        # --- desired-state rules (every policy, including no-op) ------------
        policies_checked += 1
        errors.extend(check_policy(name, after, settings))

        match = NAME_RULE.match(name)
        if match:
            number = match.group(1)
            if number in numbers_seen:
                errors.append(
                    f"{name}: number CA{number} is already used by {numbers_seen[number]}"
                )
            else:
                numbers_seen[number] = name

    if policies_checked == 0:
        print("::warning::no Conditional Access policies found in the plan; nothing was checked")

    return errors


def check_policy(name: str, after: Mapping[str, Any], settings: Settings) -> list[str]:
    """Desired-state rules for one policy's post-apply values."""
    errors: list[str] = []

    if not NAME_RULE.match(name):
        errors.append(f"{name}: name must follow CA###-Who-What-Control")

    conditions = _first(after.get("conditions"))
    users = _first(conditions.get("users"))
    apps = _first(conditions.get("applications"))
    grant = _first(after.get("grant_controls"))
    session = _first(after.get("session_controls"))

    if settings.breakglass_group_id not in (users.get("excluded_groups") or []):
        errors.append(f"{name}: must exclude the break-glass group")

    client_apps = set(conditions.get("client_app_types") or [])
    if (
        "block" in (grant.get("built_in_controls") or [])
        and (users.get("included_users") or []) == ["All"]
        and (apps.get("included_applications") or []) == ["All"]
        and client_apps & INTERACTIVE_CLIENTS
    ):
        errors.append(
            f"{name}: blocks all users on all apps for interactive clients; "
            "that would lock out every administrator"
        )

    risk_based = bool(conditions.get("sign_in_risk_levels")) or bool(conditions.get("user_risk_levels"))
    if risk_based and session.get("sign_in_frequency_interval") != "everyTime":
        errors.append(
            f"{name}: risk-based policies must set sign-in frequency to every time, "
            "or an existing session carries the risk through"
        )

    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} plan.json", file=sys.stderr)
        return 2

    with open(argv[1], encoding="utf-8") as handle:
        plan = json.load(handle)

    settings = Settings.from_env()
    problems = check(plan, settings)

    for problem in problems:
        print(f"::error::{problem}")
    print(f"guardrails: {len(problems)} problem(s) found")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
