# The adoption ladder: scan, then shadow, then enforce

Sangop is meant to be adopted without a big leap. Each step is reversible and needs one change. Use your own judgement about when to move on; nothing here is a guarantee.

## Step 1: scan (look only)

```bash
sangop scan path/to/your/code-or-config
```

Reads local files you own, prints what looks like a secret or personal identifier (always masked), changes nothing, uploads nothing. Use it first to see whether the problem exists in your project. Exit code 1 means "found something of the kind you asked to fail on" (`--fail-on secret|pii|any|none`), which is handy in CI.

## Step 2: shadow (log, do not interfere)

```python
sangop.configure(ledger_path=".sangop/audit.db")

@mcp.tool
@sangop.guard(purpose="support", pii_mode="shadow", sql_mode="shadow", sql_param="query")
def run_query(query: str) -> list[dict]: ...
```

The tool returns exactly what it returned before, and nothing is blocked. The audit log records, per call, **how many** values of each kind Sangop would have masked and whether the SQL would have been blocked (counts only, never the values). Run it against realistic traffic for a while, then read the log:

```bash
sangop audit tail --db .sangop/audit.db -n 20
sangop audit verify --db .sangop/audit.db
```

Choose this step when you are unsure about false alarms in your data, or when blocking a call would be costly. Shadow mode protects nothing by itself.

## Step 3: enforce (mask and block)

```python
@sangop.guard(purpose="support", sql_param="query",
              sql_policy=sangop.SqlPolicy(max_rows=20, require_filter_column="tenant_id"))
```

`pii_mode="tokenize"` (the default) replaces personal data with tokens before the model sees it; risky SQL (writes, DDL, missing tenant filter, bulk reads) is refused with a short message. Move here when the shadow log looks right for your data.

## Which step should I pick?

| Situation | Step |
|---|---|
| "Do we even have secrets or IDs lying around?" | 1 |
| "We cannot risk breaking a production tool" | 2, then 3 |
| "The data is sensitive and we accept some extra masking" | 3 |

Whatever you pick, read `Known limits` in the README first: Sangop finds patterns, it does not understand context (names and addresses without a pattern are not detected), and it can mask things that are not personal data. See also [SHARED_RESPONSIBILITY.md](../../SHARED_RESPONSIBILITY.md) for who is responsible for what.
