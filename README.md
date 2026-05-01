[![Validate skills and update skills catalog](https://github.com/righettod/code-assistant-skills-security-utils/actions/workflows/validate_and_update_catalog.yml/badge.svg?branch=main)](https://github.com/righettod/code-assistant-skills-security-utils/actions/workflows/validate_and_update_catalog.yml) ![MadeWitVSCode](https://img.shields.io/static/v1?label=Made%20with&message=VisualStudio%20Code&color=blue&?style=for-the-badge&logo=visualstudio) ![AutomatedWith](https://img.shields.io/static/v1?label=Automated%20with&message=GitHub%20Actions&color=blue&?style=for-the-badge&logo=github)

# Description

🧑‍💻 This folder contains coding assistant rules to guide the assistant to generate "secure" code for different types of feature.

🔬 The idea is to:

1. Convert interesting proposals from the collection of proposals of this [project](https://github.com/righettod/code-snippets-security-utils) into **rules**.
2. Allow me to learn how to create instructions for a coding assistant (claude code here) to allow to create secure code at the implementation time.

## Rules

> [!IMPORTANT]
> Adapt these templates to the specific context of the application because, by default, I applied **a very defensive** approach. Such approach perhaps do not match the context of the application and its target security posture.

> [!NOTE]
> A bundle with all the skills is available via this [file](docs/skills.zip).

> [!TIP]
> A skills catalog is available via this [file](skills_catalog.xml).

🗃️ All rules are created as [skills](https://agentskills.io/specification) and are stored into this [folder](.claude/skills).

📄 The convention to create a skills is specified into the [CLAUDE.md](CLAUDE.md) file.

## Commands

✅ In *Claude code* use the following commands:

- `/validate-skill <SKILL_NAME>` to validate the specified skills against conventions.
- `/validate-skill` to validate all skills against conventions.

## List & install skills

🧑‍💻 The tool [skills](https://github.com/vercel-labs/skills) can be used to list and install skills proposed by this repository:

```bash
# Refer to "https://github.com/vercel-labs/skills/blob/main/README.md" for more installation options
# List all proposed skills
npx -q skills@latest add righettod/code-assistant-skills-security-utils --list
# Install all proposed skills
npx -q skills@latest add righettod/code-assistant-skills-security-utils
```

## References

- <https://agentskills.io/specification>
- <https://github.com/agentskills/agentskills>
- <https://github.com/vercel-labs>
