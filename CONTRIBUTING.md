# Contributing

Keep changes small enough to review and add tests for parser, rule, or containment behavior. Rule evidence must be deterministic and must not include credential values.

Before opening a pull request, run:

```console
pytest
ruff check .
mypy
```

New rules need a stable ID, a concrete risk, a remediation, positive and negative fixtures, and a clear statement of uncertainty. Avoid rules that infer server behavior from a package name alone.

Use synthetic configurations in tests and examples. Follow `SECURITY.md` for anything that could expose private data.
