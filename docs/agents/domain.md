# Domain docs

How agents should use this repo's domain documentation when exploring or changing the
codebase.

## Before exploring, read

- **`CONTEXT.md`** at the repo root — the glossary of this project's terms.
- **`docs/adr/`** — recorded decisions, when the directory exists.

If either is missing, proceed silently. Don't flag the absence and don't scaffold
empty files; they are created when a term or a decision actually gets resolved.

## Layout

Single-context repo: one `CONTEXT.md` at the root, one `docs/adr/` (numbered
`0001-slug.md`, created lazily).

## Use the glossary's vocabulary

When output names a domain concept — in a commit message, an issue title, a test
name, a docs sentence — use the term as `CONTEXT.md` defines it and avoid the listed
synonyms. In this repo that means, for example: *admin channel*, never "management
key"; *pre-personalization* vs *personalization*, never the ambiguous "provisioning";
*genuineness* or *key attestation*, never bare "attestation".

If a concept you need isn't in the glossary, that's a signal: either you're inventing
language the project doesn't use (reconsider), or there's a real gap — extend
`CONTEXT.md` alongside the change that needed the term.

## Flag conflicts

If your output contradicts a glossary definition or a recorded decision, surface it
explicitly rather than silently overriding — say what it contradicts and why it might
be worth reopening.
