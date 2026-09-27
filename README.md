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
| 2 | CA003 (block legacy auth) deployed in report-only | in progress |
| 3 | Full seven-policy baseline in report-only | |
| 4 | Plan guardrails in Python, with tests | |
| 5 | PR plan, approval-gated apply | |
| 6 | Validate with sign-in logs and What If, enforce one at a time | |
| 7 | Daily drift detection | |

## Layout

```
.
├── policies/          Terraform root module: one file per policy
├── guardrails/        policy-as-code checks on the plan JSON, with tests
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
