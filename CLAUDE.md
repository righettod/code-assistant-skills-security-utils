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
```

Do not add fields outside the agentskills.io spec at the top level. Non-standard fields belong under `metadata`.

### Body structure

Every skill must have:

1. An intro line: *"Apply **all** rules below when generating or reviewing any code related to …"*
2. A numbered section `## 1. <Topic> (CRITICAL)` containing:
   - `ALWAYS …` rule statements (language-agnostic)
   - A Java BAD/GOOD code example illustrating every rule
3. A `## 2. Output Checklist` section with one checkbox per rule
4. A `## References` section linking to authoritative sources (OWASP, PortSwigger, etc.)

### Rule quality checklist

Before adding or modifying a skill, verify:

- Rules are language-agnostic (no Java-only wording)
- Code examples cover every stated rule — no rule without corresponding code, no code without a matching rule
- Numeric limits (sizes, counts, depths) are identical in both the rule text and the code constants
- Code snippets declare all variables they use
- Security gaps covered: path/input validation, canonical path checks, symlink/hardlink protection where relevant

## Validation

To validate a skill using the built-in Claude command:

```
/validate-skill <skill-name>   # validate a single skill
/validate-skill all            # validate all skills
```

To check a skill against the agentskills.io spec only:

```bash
skills-ref validate .claude/skills/<skill-name>
```

The `skills-ref` tool is the reference validator from [agentskills/agentskills](https://github.com/agentskills/agentskills/tree/main/skills-ref).
