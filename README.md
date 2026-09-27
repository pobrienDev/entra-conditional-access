# entra-conditional-access

Microsoft Entra Conditional Access policies as reviewed, version-controlled
Terraform: every change is a pull request with a plan, automated guardrails
block dangerous changes, applying requires approval, and a daily job detects
anyone changing policies in the portal.

Runs against a personal sandbox tenant. Sibling of
[entra-terraform](https://github.com/pobrienDev/entra-terraform), which owns
the state storage and the two pipeline identities this repo authenticates as.

## Status

| Phase | Deliverable | State |
|---|---|---|
| 0 | Break-glass accounts and group, security defaults off, strong admin methods, test users | done |
| 1 | Repo, provider, backend, `ca-plan` and `ca-apply` identities | done |
| 2 | CA003 (block legacy auth) deployed in report-only | done |
| 3 | Full seven-policy baseline in report-only | done |
| 4 | Plan guardrails in Python, with tests | done |
| 5 | PR plan, approval-gated apply | in progress |
| 6 | Validate with sign-in logs and What If, enforce one at a time | |
| 7 | Daily drift detection | |

## The baseline

Names follow `CA###-Who-What-Control` so policies sort predictably and are
easy to reference. Every policy excludes the break-glass group and was created
in report-only.

| Policy | Assignment | Control | License |
|---|---|---|---|
| `CA001-AllUsers-AllApps-RequireMFA` | All users, all apps | Require MFA | P1 |
| `CA002-Admins-AllApps-PhishingResistant` | Five privileged directory roles | Phishing-resistant authentication strength | P1 |
| `CA003-AllUsers-LegacyAuth-Block` | Exchange ActiveSync and other legacy clients | Block | P1 |
| `CA004-AllUsers-AzureMgmt-RequireMFA` | Azure management (portal, CLI, PowerShell) | Require MFA | P1 |
| `CA005-AllUsers-SignInRiskMedHigh-MFA` | Sign-in risk medium or high | MFA, sign-in frequency every time | P2 |
| `CA006-AllUsers-UserRiskHigh-PasswordChange` | User risk high | MFA **and** password change, every time | P2 |
| `CA007-AllUsers-RegisterSecInfo-TrustedOnly` | Registering security info outside trusted locations | Require MFA | P1 |

CA004 overlaps CA001 on purpose: if someone later adds an exclusion to CA001,
the management plane stays protected. CA003 exists because legacy protocols
cannot do MFA, so CA001 never applies to them; only a block stops them.

## Guardrails: the safety rules as code

CI converts the plan to JSON and `guardrails/check_plan.py` inspects every
Conditional Access policy in it. Any broken rule fails the pull request with
an annotation before it can be merged.

| Rule | What it prevents |
|---|---|
| Every policy excludes the break-glass group | A policy that could lock out every admin, including the emergency accounts |
| New policies start in report-only | Enforcing an untested policy on day one |
| Names follow `CA###-Who-What-Control`, numbers unique | Unreadable, unsortable, ambiguous policy lists |
| Deleting, replacing or disabling a policy is blocked unless `ALLOW_CA_DELETE=true` | Silently removing protection; removal should be a deliberate, reviewed decision |
| No All users + All apps + Block for interactive clients | The classic self-lockout. CA003 passes because it only targets legacy clients |
| Risk-based policies use sign-in frequency every time | An existing session carrying a risky sign-in through unchallenged |

Two design choices worth knowing. The desired-state rules run against every
policy in the plan, not just the ones changing, so a policy that drifted in
the portal and was then adopted into code still fails. And the script fails
closed: a value Terraform cannot know until apply time counts as wrong.

The break-glass group ID comes from CI configuration, never the repository,
so a pull request cannot redefine which group must be excluded.

Tests build small plans in the real `terraform show -json` shape, plus one
redacted plan captured from the tenant so the fixtures cannot drift from
reality:

```bash
pip install -r guardrails/requirements-dev.txt
pytest guardrails
```

The same checks could be written in Rego for Open Policy Agent and run with
Conftest, which is the more common tool for this. Python keeps them in the
stack the rest of my projects use, with no extra binary in CI.

## Layout

```
.
├── policies/          Terraform root module: one file per policy
├── guardrails/        check_plan.py and its tests; standard library only
├── .github/workflows/ plan on PR, approval-gated apply, daily drift
└── .githooks/         blocks IDs, secrets and state from being committed
```

## Safety rules

- Sandbox tenant only.
- Two break-glass accounts live in a group created by hand. Terraform only
  reads that group, and refuses to plan if it has fewer than two members.
- Every policy excludes the break-glass group. A guardrail enforces it.
- New policies are created in report-only. A guardrail enforces it.
- Deleting a policy fails CI unless explicitly allowed.
