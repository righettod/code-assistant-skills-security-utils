Validate skill(s) in this repository using the authoring rules and quality checklist defined in `CLAUDE.md`.

- If $ARGUMENTS is a skill name, validate only `.claude/skills/$ARGUMENTS/SKILL.md`.
- If $ARGUMENTS is empty or `all`, validate every skill found under `.claude/skills/`.

For each skill, apply the three validation criteria from `CLAUDE.md`:

1. **Spec validity** — frontmatter fields per the agentskills.io + Claude Code spec.
2. **Correctness** — rules match code examples, numeric limits are consistent, all variables are declared.
3. **Effectiveness** — language-agnostic rules, checklist maps to rules, references present, no security gaps for the threat domain.

## Output format

For each skill:

### `<skill-name>` — [PASS | ISSUES FOUND]

| Check | Status | Detail |
|---|---|---|
| Spec validity | ✅ / ❌ | … |
| Correctness | ✅ / ⚠️ / ❌ | … |
| Effectiveness | ✅ / ⚠️ / ❌ | … |

List each individual issue below the table. End with a summary: `X/Y skills passed all checks.`
