# Let us secure business
Here is a bunch of app sec automation scripts written in Python. Any contribution is welcome both on Cloud or app sec
# AMAZON IAM BASIC CONTROLS
Developed with [Boto3](https://pages.github.com/).
AWS [AWS APIs](https://aws.amazon.com/sdk-for-python/)

# APPLICATION SECURITY SCANNERS UNIFICATION
SAST
  Semgrep
  Sonarqube
SCA
  Trivy
  Mend
Secret Scanner
  Detect-Secrets
# Scan Tools Mediator
This tool collects various scan tools' findings over json files or scan tool APIs and unifies them into a json file with outstanding fields.
  Supported tools:
    Semgrep
    Trivy
    Sonar
    Mend SCA
    Detect-Secrets
    
  Dups findings are removed yet a confirmation msg is set for the duplicated finding to highlight many tools spot the finding
  Slack,Jira, AWS S3 integrations are tested and running to notify related teams instantly
