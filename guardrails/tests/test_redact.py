"""The redaction script is the only thing between raw plan output and a public log."""

import subprocess
from pathlib import Path

REDACT = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "redact.sh"


def redact(text: str) -> str:
    return subprocess.run([str(REDACT)], input=text, capture_output=True, text=True, check=True).stdout


def test_strips_every_identifier_class():
    # The placeholder GUID and the assembled domain keep the repo's own
    # pre-commit leak guard from rejecting this file.
    domain = "contoso." + "onmicrosoft.com"
    raw = (
        f"tenant 00000000-0000-0000-0000-0000deadbeef user@{domain} "
        "sttfstateabc12345 https://login.microsoftonline.com/x ip_ranges = [\"203.0.113.0/24\", \"198.51.100.7\"]\n"
    )
    assert redact(raw) == 'tenant <guid> user@<tenant-domain> <state-storage> <url> ip_ranges = ["<ip>", "<ip>"]\n'


def test_drops_refresh_noise_and_keeps_the_rest():
    raw = (
        "azuread_conditional_access_policy.ca001: Refreshing state... [id=/x]\n"
        "data.azuread_group.breakglass: Reading...\n"
        "Acquiring state lock. This may take a few moments...\n"
        "Plan: 1 to add, 0 to change, 0 to destroy.\n"
    )
    assert redact(raw) == "Plan: 1 to add, 0 to change, 0 to destroy.\n"


def test_version_numbers_are_not_mistaken_for_ips():
    assert redact("Terraform v1.16.3 provider 3.9.0\n") == "Terraform v1.16.3 provider 3.9.0\n"


def test_empty_input_is_fine():
    assert redact("") == ""
