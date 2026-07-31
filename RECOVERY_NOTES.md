# Recovery Notes

This folder is the reconstructed pre-loss `auto-re-agent` project assembled from:

1. the strongest surviving Git object tree (`4a3be0770cac4fe7ebc324ad01db060b07e9d4ee`), which matches the final Codex checkpoint of **360 passed + 2 skipped**; and
2. the later Gemini conversation/tool log, replayed on top of that baseline.

## Verification performed

- Python syntax compilation: passed for `src/` and `tests/`.
- Pytest collection with `PYTHONPATH=src`: **369 tests collected**.
- This matches the recorded final state of **367 passed + 2 skipped**.

## Important limitation

This is the strongest transcript-and-object reconstruction available, not a cryptographic byte-for-byte snapshot of the deleted working directory. Generated artifacts and secrets are intentionally excluded. Review the included patch before replacing any existing workspace.

## Safe use

Extract into a new directory. Do not overwrite the current repository. Compare it against your existing recovery branch, then commit the reviewed state on a new branch.
