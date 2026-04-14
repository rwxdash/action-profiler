Generate a commit title and description for the current staged changes.

Follow the format from CLAUDE.md:

**PR Title:** Short, generic, imperative phrase, no period, max ~28 chars.
**Suggested Branch Name:** A descriptive, short branch name with either `impl/` or `fix/` prefix. Max ~28 chars.

**Title:** Short imperative phrase, no period, max ~72 chars.

**Description:**
```
One or two sentences summarising the goal/motivation of the change.

- component: what changed (use action, ebpf, etc. prefixes)
- component: what changed
- ...
```

Steps:
1. Run `git status -u --short` and `git diff --staged --stat` and `git diff --stat` to see what changed
2. Read the diff if needed to understand what changed
3. Generate the commit message following the format above
4. Do NOT create the commit, just output the message
