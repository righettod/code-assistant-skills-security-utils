![MadeWitVSCode](https://img.shields.io/static/v1?label=Made%20with&message=VisualStudio%20Code&color=blue&?style=for-the-badge&logo=visualstudio)  ![AutomatedWith](https://img.shields.io/static/v1?label=Automated%20with&message=GitHub%20Actions&color=blue&?style=for-the-badge&logo=github)

# Description

🧑‍💻 This folder contains coding assistant rules to guide the assistant to generate "secure" code for different types of feature.

🔬 The idea is to:

1. Convert the collection of proposals from this [project](https://github.com/righettod/code-snippets-security-utils) into **rules**.
2. Allow me to learn how to create instructions for a coding assistant (claude code here) to allow to create secure code at the implementation time.

## Rules

🗃️ All rules are created as [skills](https://agentskills.io/specification) and are stored into this [folder](.claude/skills).

📄 The convention to create a skills is specified into the [CLAUDE.md file](CLAUDE.md).

## Commands

✅ In *Claude code* use the following commands:

- `/validate-skill <SKILL_NAME>` to validate the specified skills against conventions.
- `/validate-skill` to validate all skills against conventions.

## References

- <https://agentskills.io/specification>
- <https://github.com/agentskills/agentskills>
