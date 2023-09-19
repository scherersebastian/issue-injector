# Issue Injector

**IssueInjector** is a GitHub Action that excels in turning security findings, especially those in the SARIF (Static Analysis Results Interchange Format), into actionable GitHub Issues.

This makes it extremely versatile, compatible with almost any security tool that exports findings in the SARIF format.

Acting as a bridge between your security scan outputs and your GitHub Issues tab, it auto-populates issues based on identified vulnerabilities, risks, or areas that need attention.

By handling this conversion seamlessly, IssueInjector allows your team to shift their focus from identification to immediate action and resolution.

In essence, it's an automated, highly adaptable triage system for your code's security, facilitating quicker fixes and a more secure end product.

With this Action, you can bypass the GitHub Advanced Security Dashboard.

## How To Use

The Issue Injector GitHub Action processes SARIF files to create GitHub issues based on the findings. It filters findings based on severity and ensures that issues are properly labeled.

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

      - name: Use Issue Injector
        uses: scherersebastian/issue-injector@v1.0.0 # replace `v1` with the version you'd like to use
        with:
          SARIF_FILE: "path/to/your/sarif-file.sarif"
          SEVERITY: "error" # Optional, default is "error"
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPO: "username/repo-name"
```

2. _Set Required Secrets:_ Make sure to set the GITHUB_TOKEN secret to `contents: read, issues: write`.

3. _Run the Workflow:_ Once your workflow file is set up, push the changes to your GitHub repository. This will trigger the workflow, and the Issue Injector action will process the SARIF file and create issues based on the findings.

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
