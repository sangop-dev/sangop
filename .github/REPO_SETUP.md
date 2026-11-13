# GitHub repository setup (draft, applied by hand by the maintainer)

Nothing here is active. The maintainer copies these values into the GitHub settings of the public repository.

## About box

- **Description** (119 characters): `Local guard for AI agent tools: masks Indian personal data and secrets, blocks unsafe SQL, keeps a verifiable audit log`
- **Website:** leave empty until the project site exists.
- **Topics:** `mcp`, `fastmcp`, `pii`, `dpdp`, `india`, `aadhaar`, `llm-security`, `ai-agents`, `data-masking`, `audit-log`

## Social preview image (1280 x 640, made later by the maintainer; no third-party logos)

- Line 1: **Sangop**
- Line 2: Local guard for AI agent tools
- Line 3: masks Indian personal data · blocks unsafe SQL · verifiable audit log
- Small footer: Apache-2.0 · Python 3.10+ · runs inside your process, no network

## Discussions: three categories

1. **Q&A** (answers can be marked): installing, configuring `@guard`, reading the ledger.
2. **False positives and misses** (open-ended): a value that was masked but should not be, or the other way round.
   Synthetic examples only; never paste real personal data or real keys.
3. **Ideas** (open-ended): new secret formats, examples, docs. Not for security issues: those go through
   `SECURITY.md` (private report).

## Security settings (turn on before the repository becomes public)

In the repository's **Settings**, in the "Security" part of the sidebar (GitHub calls the page "Advanced Security";
some views say "Security and quality"):

1. **Private vulnerability reporting:** Enable. `SECURITY.md` and the issue form's "Security issue (private)" link
   send reporters there.
2. **Secret scanning** (Secret Protection; free for public repositories): Enable.
3. **Push protection** (under Secret Protection): Enable, so a push that contains a recognised secret is blocked.

Also check: **Dependabot alerts** on (public repositories have them by default).

## Ideas for later (Discussions)

External pull requests are not accepted yet (`CONTRIBUTING.md`), so these are not issues for others to take. The
maintainer may post them under Discussions > Ideas to see which ones people want:

1. Recognise Hugging Face access tokens (`hf_...`) as a secret.
2. Recognise Stripe secret keys (`sk_live_...`, `rk_live_...`); the README lists them as not recognised today.
3. An example: a guarded tool over a read-only SQLite database (20 lines or fewer).
4. Docs: a table of the SQL guard's block messages, what each means and how to fix the query or the policy.
5. `sangop sql-check --json`: machine-readable output for use in CI scripts.
