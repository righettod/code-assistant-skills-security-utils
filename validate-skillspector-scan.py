"""
Check the result of SkillSpector using the json report.
"""

import json
import sys

# Ignored issues: See "README.md" for explanations
IGNORED_ISSUES = ["|id=pe3|category=privilege escalation|pattern=credential access|file=skills/secure-jwt-validation/skill.md|"]

# Main code
with open(sys.argv[1], mode="r", encoding="utf-8") as f:
    report_data = json.load(f)
issues = report_data["issues"]
issues_count = 0
for issue in issues:
    issue_id = issue["id"]
    issue_category = issue["category"]
    issue_pattern = issue["pattern"]
    issue_file = issue["location"]["file"]
    ignored_issue_id = (f"|id={issue_id}|category={issue_category}|pattern={issue_pattern}|file={issue_file}|").lower()
    if ignored_issue_id not in IGNORED_ISSUES:
        issues_count += 1
print(f"{report_data['analysis_completeness']['scanned_components']}/{report_data['analysis_completeness']['total_components']} skills scanned with SkillSpector version {report_data['metadata']['skillspector_version']}")
print(f"{issues_count} issue(s) identified once ignored issues taken in account (issues count used as RC).")
sys.exit(issues_count)
