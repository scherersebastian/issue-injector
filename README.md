# IssueInjector

**IssueInjector** is a GitHub action adept at converting security findings, notably from SARIF (Static Analysis Results Interchange Format), into GitHub issues. It not only creates issues for new findings but also auto-closes resolved ones.

This tool is compatible with nearly all security tools that use the SARIF format. It bridges the gap between security scan results and your GitHub issues tab, automatically generating issues from detected vulnerabilities and risks.

A distinguishing feature of IssueInjector is its capability to _bypass the GitHub Advanced Security Dashboard_. This means users can view and manage findings directly in GitHub, even _without the Advanced Security_ subscription, eliminating the need to switch between platforms for each security tool.

## How To Use

The IssueInjector GitHub Action processes SARIF files to create GitHub issues based on the findings. It filters findings based on severity and ensures that issues are properly labeled.

### Prerequisites

Make sure you have a SARIF file that you want to process. Your GitHub repository should have the following variables:

- **SARIF_FILE**: The path to your SARIF file.

- **SEVERITY**: The severity level to filter the findings (optional, default is "error").

- **GITHUB_TOKEN**: GitHub token to authenticate with the API.

- **GITHUB_REPO**: The GitHub repository where issues should be created.

### Setup Instructions

1. _Add Action to Your Workflow File:_ In your GitHub Actions workflow, you can include this action by creating a new step.

```yml
jobs:
  your_job_name:
    runs-on: ubuntu-latest

    permissions:
      contents: read
      issues: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Use IssueInjector
        uses: scherersebastian/issue-injector@v1.0.0 # replace `v1` with the version you'd like to use
        with:
          SARIF_FILE: "path/to/your/sarif-file.sarif"
          SEVERITY: "error" # Optional, default is "error"
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPO: "username/repo-name"
```

2. _Set Required Secrets:_ Make sure to set the GITHUB_TOKEN secret to `contents: read, issues: write`.

3. _Run the Workflow:_ Once your workflow file is set up, push the changes to your GitHub repository. This will trigger the workflow, and the IssueInjector action will process the SARIF file and create issues based on the findings.

4. _Check for Issues:_ After the workflow runs, check your GitHub repository's "Issues" tab for newly created issues.

### Inputs

| Input          | Description                                          | Required | Default |
| -------------- | ---------------------------------------------------- | -------- | ------- |
| `SARIF_FILE`   | Path to the SARIF file                               | Yes      |         |
| `SEVERITY`     | Severity level to filter                             | No       | `error` |
| `GITHUB_TOKEN` | GitHub token to authenticate with the API            | Yes      |         |
| `GITHUB_REPO`  | The GitHub repository where issues should be created | Yes      |         |

## Limitations

- Once closed, issues remain closed: If an issue is manually closed, the script won't reopen it even if the finding reappears in a new scan.

- No branch support: The current version of the script doesn't distinguish between different branches. It assumes that all findings are relevant to the default or main branch.

- Location changes result in hash mismatch: If the location of a finding is changed, such as by renaming a file, the hash generated for that finding will differ. This could lead to duplicate issues being created.

## License

The scripts and documentation in this project are released under the MIT License.
