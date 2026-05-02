# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

This repository converts secure coding patterns from [code-snippets-security-utils](https://github.com/righettod/code-snippets-security-utils) into Claude Code **skills** — reusable instruction sets that guide code generation toward secure implementations.

## Repository Structure

Skills live in `.claude/skills/<skill-name>/SKILL.md`. Each skill follows the [agentskills.io specification](https://agentskills.io/specification).

## Skill Authoring Rules

### Frontmatter (valid fields only)

```yaml
name: skill-name              # must match directory name; lowercase, hyphens only
description: ...              # what it does and when to invoke it
allowed-tools: Read Grep Glob # tools the skill may use without approval
metadata:
  category: security          # all skills in this repo use category: security
  security-considerations:    # optional, provide information about threats not covered or strictness of controls applied.
    - ... 
```

Do not add fields outside the `agentskills.io` spec at the top level. Non-standard fields belong under `metadata`.

Mandatory or optional presence of fields in the section `metadata`:

- `security-considerations` is **optional**.
- `category` is **mandatory**.

### Body structure

Every skill must have:

1. An intro line: *"Apply **all** rules below when generating or reviewing any code related to …"*.
2. A numbered section `## 1. <Topic> (CRITICAL)` containing:
   - `ALWAYS …` rule statements (language-agnostic).
   - A Java BAD/GOOD code example illustrating every rule.
3. A `## 2. Output Checklist` section with one checkbox per rule.
4. A `## References` section linking to one or several of the following authoritative sources: OWASP, PORTSWIGGER, MITRE, NIST, ANSSI, SANS, MICROSOFT, ECMA.
5. A *Frontmatter section* fully valid according to the rules defined in the section `Frontmatter (valid fields only)`.

### Code snippet formatting rules

When writing or editing code snippets inside a skill:

- **Never wrap lines at 80 columns.** Write each logical statement on a single line regardless of length.
- **Never add alignment padding.** Do not insert extra spaces to align operators, arguments, or comments across lines.
- Let the reader's editor handle soft-wrapping.

### Rule quality checklist

Before adding or modifying a skill, verify:

- Rules are language-agnostic (no Java-only wording).
- Code examples cover every stated rule — no rule without corresponding code, no code without a matching rule.
- Numeric limits (sizes, counts, depths) are identical in both the rule text and the code constants.
- Code snippets declare all variables they use.
- Security gaps covered: No case is missing.
- Skill follow a consistent `secure-<subject>-<action>` naming pattern.
- Code snippets follow the formatting rules defined into the section `Code snippet formatting rules` (no 80-column wrapping, no alignment padding).

## Validation

To validate a skill using the built-in Claude command:

```text
/validate-skill <skill-name>   # validate a single skill
/validate-skill all            # validate all skills
```

To check a skill against the agentskills.io spec only:

```bash
agentskills validate .claude/skills/<skill-name>
```

The `skills-ref` tool is the reference validator from [agentskills/agentskills](https://github.com/agentskills/agentskills/tree/main/skills-ref).
