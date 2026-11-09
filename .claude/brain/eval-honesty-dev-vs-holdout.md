# Eval honesty: dev vs holdout

Summary: rules were tuned on `evals/data/*`; `evals/data/holdout/*` was written after the rules were frozen. Never tune on holdout.

- `first_run_before_tuning` in `evals/results.json` keeps the untuned dev numbers. The runner never overwrites it.
- If you change rules, write a NEW holdout set first, then run. Do not edit the old holdout to make it pass.
- Headline claims in the README must use holdout numbers for generalization.
- All sets have the same author as the rules, so even holdout numbers are optimistic.
