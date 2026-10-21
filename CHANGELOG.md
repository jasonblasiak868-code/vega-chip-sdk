# Changelog

## 2026-10-20: fixes found by a source read

These were found by reading the source against its own documentation after release, not by the earlier test and review passes. Each fix has a regression test in
`tests/test_findings_20261020.py` that failed before the fix, and each fix was checked by undoing it and confirming a test fails. Behaviour that changed is listed under "Changed".

### Fixed
- **The gate unit was not safe to call from threads.** Two threads could use one grant twice, or spend one approval on two ports, and concurrent writes tore the non-volatile record and failed the unit until restart. The unit's operations now run one at a time.
