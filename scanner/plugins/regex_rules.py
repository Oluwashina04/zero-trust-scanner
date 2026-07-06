import re

# This is our dictionary of secret patterns!
# The left side is the "name" of the secret.
# The right side is the "pattern" (regex) to find it.
RULES = {
    "AWS_Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS_Secret": re.compile(r"[A-Za-z0-9/+=]{40}"),
    "GitHub_Token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "Slack_Token": re.compile(r"xox[baprs]-[A-Za-z0-9-]+"),
    "Stripe_Key": re.compile(r"sk_live_[A-Za-z0-9]{24}"),
}

def scan_with_regex(content: str) -> list:
    """Scan text content for secrets using regex patterns."""
    findings = []
    
    # Loop through each rule (e.g., AWS_Key, GitHub_Token)
    for rule_name, pattern in RULES.items():
        # Find all matches in the content
        for match in pattern.finditer(content):
            # Save the finding
            findings.append({
                "type": rule_name,          # e.g., "AWS_Key"
                "match": match.group(),     # e.g., "AKIAIOSFODNN7EXAMPLE"
                "span": match.span()        # Where it was found (start/end position)
            })
    
    return findings
