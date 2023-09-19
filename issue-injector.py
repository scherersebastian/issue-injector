import json
import os
import hashlib
import requests

def check_file_exists(file_path):
    """Check if the specified file exists."""
    return os.path.exists(file_path)

def read_sarif(file_path):
    """Read a SARIF file and return its content as a JSON object."""
    with open(file_path, 'r') as f:
        return json.load(f)

def filter_findings_by_severity(sarif_data, severity):
    """Filter SARIF findings by severity."""
    findings = sarif_data['runs'][0]['results']
    rules = {rule['id']: rule for rule in sarif_data['runs'][0].get('tool', {}).get('driver', {}).get('rules', [])}

    filtered_findings = []
    for finding in findings:
        rule_id = finding.get('ruleId')
        if rule_id:
            rule = rules.get(rule_id)
            if rule:
                rule_severity = rule.get('defaultConfiguration', {}).get('level')
                if rule_severity == severity:
                    filtered_findings.append(finding)

    return filtered_findings

def generate_hash(finding):
    """Generate a hash for a SARIF finding.

    Example finding, startColumn not present - get method: If the key is not found in the dictionary, the method returns a default value, which is an empty string in this case.:
    {
        "ruleId": "fd54f200-402c-4333-a5a4-36ef6709af2f",
        "ruleIndex": 0,
        "kind": "fail",
        "message": {
            "text": "The 'Dockerfile' does not contain any 'USER' instruction"
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": "test/missing_user_instruction-positive.dockerfile"
                    },
                    "region": {
                        "startLine": 2
                    }
                }
            }
        ]
    }
    """
    rule_id = finding['ruleId']
    location = finding['locations'][0]['physicalLocation']['artifactLocation']['uri']
    region = finding['locations'][0]['physicalLocation']['region']
    start_line = region['startLine']
    return hashlib.sha256(f"{rule_id}{location}{start_line}".encode()).hexdigest()

def get_github_issues(token, repo, labels):
    """Get GitHub issues with specified labels."""
    url = f"https://api.github.com/repos/{repo}/issues"
    headers = {'Authorization': f'token {token}'}
    params = {'labels': ','.join(labels), 'state': 'all'} # Get both open and closed issues
    r = requests.get(url, headers=headers, params=params)
    if r.status_code == 200:
        return r.json()
    else:
        print(f"Failed to get GitHub issues: {r.content}")
        return []

def close_github_issue(token, repo, issue_number):
    # Close the issue
    url = f"https://api.github.com/repos/{repo}/issues/{issue_number}"
    headers = {'Authorization': f'token {token}'}
    data = {"state": "closed"}
    r = requests.patch(url, headers=headers, json=data)
    if r.status_code == 200:
        print(f"Closed issue {issue_number}.")
    else:
        print(f"Failed to close issue {issue_number}: {r.content}")

def create_github_issue(token, repo, rule, hash_id, finding, labels):
    """Create a GitHub issue."""    
    url = f"https://api.github.com/repos/{repo}/issues"
    headers = {'Authorization': f'token {token}'}
    rule_name = rule.get('name', 'Unknown Rule')
    data = {
        "title": rule_name,
        "body": f"Hash ID: {hash_id}\n```json\n{json.dumps(finding, indent=4)}\n{json.dumps(rule, indent=4)}\n```",
        "labels": labels
    }
    r = requests.post(url, headers=headers, json=data)
    if r.status_code == 201:
        print(f"Created issue for {rule_name}.")
    else:
        print(f"Failed to create issue: {r.content}")

def get_tool_name(sarif_data):
    """Get the name of the tool that generated the SARIF report."""
    tool_section = sarif_data['runs'][0].get('tool', {})
    driver_section = tool_section.get('driver', {})
    tool_name = driver_section.get('name', '')
    return tool_name

def ensure_github_labels(token, repo, labels):
    """Ensure that the given labels exist in the GitHub repository."""
    url = f"https://api.github.com/repos/{repo}/labels"
    headers = {'Authorization': f'token {token}'}
    
    # Get existing labels
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        print(f"Failed to get labels: {r.content}")
        return
    existing_labels = [label['name'] for label in r.json()]

    # Create missing labels
    for label in labels:
        if label not in existing_labels:
            data = {"name": label, "color": "ffffff"}
            r = requests.post(url, headers=headers, json=data)
            if r.status_code == 201:
                print(f"Created label {label}.")
            else:
                print(f"Failed to create label {label}: {r.content}")

def find_rule_by_id(sarif_data, rule_id):
    """
    Find the rule object that matches the given rule_id in the SARIF data.

    Parameters:
        sarif_data (dict): The parsed SARIF data.
        rule_id (str): The id of the rule to find.

    Returns:
        dict: The rule object, or None if not found.
    """
    try:
        rules = sarif_data['runs'][0]['tool']['driver']['rules']
    except KeyError:
        print("The SARIF file does not contain rule definitions.")
        return None
    
    for rule in rules:
        if 'id' in rule and rule['id'] == rule_id:
            return rule
    
    return None

def main():
    # Read environment variables
    sarif_file = os.getenv('SARIF_FILE')
    severity = os.getenv('SEVERITY')
    github_token = os.getenv('GITHUB_TOKEN')
    github_repo = os.getenv('GITHUB_REPO')

    # Check SARIF file
    if not check_file_exists(sarif_file):
        print("SARIF file not found.")
        return

    # Read SARIF file
    sarif_data = read_sarif(sarif_file)

    # Filter findings by severity
    filtered_findings = filter_findings_by_severity(sarif_data, severity)
    if not filtered_findings:
        print("No findings with the given severity found.")
        # return

    print(f"Found {len(filtered_findings)} findings with severity {severity}.")
    print(f"Filtered findings: {json.dumps(filtered_findings, indent=4)}")

    # Generate hashes for the findings
    finding_hashes = {generate_hash(finding): finding for finding in filtered_findings}

    # Get tool name
    tool_name = get_tool_name(sarif_data)
    labels = ['security', tool_name]
    
    # Ensure GitHub labels
    ensure_github_labels(github_token, github_repo, labels)

    # Create or close GitHub issues based on findings
    existing_issues = get_github_issues(github_token, github_repo, labels)

    for issue in existing_issues:
        hash_id = issue['body'].split("Hash ID: ")[1].split("\n")[0]
        if hash_id not in finding_hashes:
            close_github_issue(github_token, github_repo, issue['number'])

    for hash_id, finding in finding_hashes.items():
        if not any(hash_id in issue['body'] for issue in existing_issues):
            # Create a new issue
            rule = find_rule_by_id(sarif_data, finding['ruleId'])
            create_github_issue(github_token, github_repo, rule, hash_id, finding, labels)

if __name__ == "__main__":
    main()
