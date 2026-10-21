# vega-chip-sdk — Specification

Spec v1.0 — 2026-10-19 — describes the published reference implementation as tested; where this document and the source disagree, the source wins.

## 1. Purpose and scope

This specification describes the **vega-chip-sdk**: a software reference model of the governance hardware (silicon and photonic embodiments) comprising four modules:

- **nv** — two physically separate non-volatile regions with hash-chained records, read-back before trust, torn-write recovery, and injectable faults.
- **geu** — the Governance Enforcement Unit: write-once key store, signature verifier, nonce burn in non-volatile memory, monotonic lease clock, hash-chain appender, output gate per port (closed by default), hard stop, DMA side-door table.
- **pre_unit** — the PRE runtime unit: pre-registered workflows (locked with a human commitment) that run step-by-step with code/input/output hash verification, budget metering, result hash appended to chain before release; unlocked workflows run in quarantine; accelerator results are tainted unless a locked output hash vouches for them.
- **conformance** — differential conformance test suite: the same signed attempts run through the software jacket (vega-governance-jacket-sdk) and the GEU; any decision mismatch is a finding.

**In scope:** the decision rules, the order of checks, the recovery rules, the PRE workflow rules, and the conformance vectors. **Out of scope:** physical timing, power, area; FPGA/silicon implementation (DESIGNED ONLY); photonic accelerator internals (treated as untrusted compute); hardware key storage; expert-reviewed cryptography.

## 2. Vocabulary

| Term | Definition |
|---|---|
| **commitment** | A human-signed note: {nonce, expiry, signature} over a specific action and parameters. Single-use, non-transitive. |
| **nonce** | A random string chosen by the human; its SHA-256 is burned in non-volatile memory before the gate opens. |
| **burn** | Append the nonce hash to both NV regions and read back; if it fails, the unit faults and nothing opens. |
| **grant** | A runtime object (port, action_hash, expiry, used=False) returned by `GEU.request`; valid for exactly one transaction. |
| **action hash** | Deterministic hash of the parameters (via `vega_jacket.humanauth.verify.action_hash`). |
| **lease** | The time window from `now` to `expiry`; capped at `MAX_LEASE_SECONDS` (900s) from the jacket. |
| **hard stop** | A global stop anyone can engage; all grants cleared; only a human commitment for `restore_after_hard_stop` can lift it. |
| **side door** | A bypass attempt (compute writing to a port without the gate token); always denied, recorded, optionally trips hard stop. |
| **DMA table** | Human-signed configuration mapping initiators to allowed ports; checked on `egress`. |
| **PRE workflow** | An ordered list of steps, each with code hash, input hash, optional output hash, and budgets. Locked with a human commitment. |
| **quarantine** | Unlocked workflow execution; results wrapped in `Quarantined`; output gate refuses them. |
| **taint** | Accelerator result without a locked output hash; wrapped in `Tainted`; output gate refuses it. |
| **conformance** | The property that the GEU and the software jacket decide identically on every vector. |

## 3. Components

### 3.1 nv — non-volatile memory model

**Role:** Provides two physically separate append-only regions with hash-chained records, read-back verification, and power-cut recovery.

**Public interface:**
- `NVFault` — exception raised on damage anywhere but a torn last line.
- `PowerCut` — exception raised by fault injector mid-write.
- `Region(path)` — single region; `read_raw()`, `write_line(line)`, `valid_prefix() -> (records, torn_tail)`.
- `NVStore(path_a, path_b)` — dual region; `head` property; `append(data) -> record`; `find(key, value) -> list[record]`.
- `NVStore._recover()` — called on init; discards torn tails, repairs one-record gaps, faults on divergent histories or gaps >1.

**Behavior:** `append` writes to both regions, flushes, fsyncs, then reads back both and compares to the intended record. On mismatch: raises `NVFault`, unit must treat as failed. Recovery discards interrupted last write (safe because no action depended on it). One-region-ahead is repaired from the other. Any other difference: `NVFault`, unit refuses to start.

**Invariants:**
- Records are append-only, hash-chained (`prev` links to prior `sha256`).
- Both regions hold identical byte sequences after every successful `append`.
- A torn last line is always discarded on recovery.
- The unit never guesses which history is true on divergence.

### 3.2 geu — Governance Enforcement Unit

**Role:** The gate on the only path from compute to the outside world. Enforces the exact order of checks; burns nonce before opening; one transaction per grant.

**Public interface:**
- `Denied(reason)` — exception with `.reason` string.
- `MonotonicClock(start)` — `read()`, `advance(n)` (only forward).
- `GEU(store, clock, ports=("net","disk","display"), device="dev", surface="surf", trip_on_side_door=True)`
  - `program_keys(pubs)` — write-once, 1–4 Ed25519 public keys (32 bytes each).
  - `request(action, params, signed, port) -> Grant` — full check sequence.
  - `transact(grant, payload) -> int` — one write on the granted port.
  - `hard_stop()` — engage stop.
  - `restore(signed)` — lift stop (human-only commitment for `restore_after_hard_stop`).
  - `program_dma(table, signed)` — set DMA side-door table (human-only `change_gate_config`).
  - `egress(initiator, port, payload, grant) -> int` — DMA path.
  - `raw_port_write(port, payload)` — bypass attempt (denied, recorded, trips stop if configured).
  - `chain() -> list[record]` — full decision chain.
  - `port_names()`, `port_log(name)` — introspection.

**Behavior:** On `request`, the unit checks in order: (1) healthy/not hard-stopped, (2) port exists, (3) keys programmed, (4) action not wildcard/odd-spelling, (5) params valid, (6) commitment fields present, (7) nonce not burned, (8) expiry > now, (9) lease ≤ cap, (10) signature valid under a programmed key, (11) burn nonce (append + read-back), (12) append GRANTED decision (read-back). First failure: deny, record, raise `Denied`. On success: returns `Grant`. `transact` verifies grant matches open grant for port, not used, not expired, payload is bytes; then writes through port (gate token required). `hard_stop` engages immediately; `restore` requires valid human commitment for `restore_after_hard_stop` and re-appends `restore` op. `program_dma` requires human commitment for `change_gate_config` over the exact canonical table. `egress` checks DMA table then calls `transact`. `raw_port_write` always denies, records `side_door`, trips hard stop if `trip_on_side_door`. Clock rollback detected at init: if clock < last recorded `t`, unit faults.

**Invariants:**
- Keys written once (`keys_blown` on repeat).
- Nonce burned exactly once (`replay` on repeat).
- Burn comes before gate opens (power cut cannot leave approval both spent and unused).
- One transaction per grant (`gate_closed` on reuse).
- Grant expires at `expiry` (checked at `transact`).
- Hard stop survives restart (recorded in chain).
- DMA table changes only via human-signed commitment.

### 3.3 pre_unit — PRE runtime unit

**Role:** Secure boot for workflows. Locked workflows run step-by-step with verification; unlocked run in quarantine; accelerator results tainted unless vouched.

**Public interface:**
- `Trap(reason)`, `Quarantined(value)`, `Tainted(value, producer="accelerator")`
- `Meter(budget, unit, run, step)` — `charge(tokens, nbytes, seconds)`; traps on budget exceed.
- `PREUnit(geu)` — `lock(workflow, steps, signed)`, `revoke(workflow, signed)`, `begin(workflow) -> Run`, `locked` dict.
- `Run(unit, workflow, steps_or_None)` — `step(step_id, code, inputs, fn, accelerator=False) -> bytes|Quarantined|Tainted`, `complete() -> bool`, `quarantined` property, `done`, `pos`.

**Behavior:** `lock` validates steps (1–200, unique ids matching `^[a-z0-9][a-z0-9_.-]{0,59}$`, code/input/output hashes 64-hex, budgets non-negative ints for tokens/bytes/seconds), checks not already locked, calls `geu._check("lock_pre", {...}, signed)`, appends `pre_lock` record. `revoke` requires human commitment for `revoke_authority`. `begin` returns `Run` with `steps` if locked, else `None` (quarantined). `Run.step`: if locked, verifies order, code hash, input hash; creates `Meter` with step budget; calls `fn(meter)`; result must be bytes; hash appended to chain BEFORE release; if output hash locked, must match; if quarantined, returns `Quarantined`; if accelerator and no locked output hash, returns `Tainted`. Budget exceed, crash, non-bytes, hash mismatch all trap and release nothing.

**Invariants:**
- Locked workflow cannot be silently replaced (`already_locked`).
- Steps run in declared order; deviations trap before execution.
- Result hash on chain before result released.
- Quarantined results cannot pass output gate (`bad_payload`).
- Tainted results cannot pass output gate (`bad_payload`).
- Locks and revocations survive restart (read from chain).

### 3.4 conformance — differential conformance suite

**Role:** Proves the GEU decides identically to the software jacket on every signed attempt.

**Public interface:**
- `run_conformance(directory=None) -> {"vectors", "attempts", "mismatches"}`

**Behavior:** Builds fresh rig per vector (so spent commitments don't leak). Vectors cover: good commitment, replay, expired, expiry at now, lease over cap, lease at cap, signed for other action, signed for other params, wildcard actions, odd spelling of human-only, human-only signed correctly, flipped signature bit, missing nonce, missing signature, expiry as float/bool/word, nonce with field separator, look-alike action name (non-ASCII), another key, another device, good after refused, junk commitment. Each vector has multiple steps with expected allow/deny. Returns mismatches list.

**Invariants:**
- Fresh rig per vector (isolation).
- Same signed bytes fed to both jacket and GEU.
- Fixed clock (`NOW = 1_900_000_000`) so expiry means the same to both.
- Any mismatch (soft != hw != expected) is a finding.

## 4. Guarantees and non-guarantees

### Guarantees

| Guarantee | Module | Test |
|---|---|---|
| Records are hash-chained and identical in both NV regions after every append | nv | `test_records_are_chained_and_read_back_from_both_regions` |
| Power cut mid-write is discarded; no action ever depended on it | nv | `test_a_power_cut_mid_write_is_discarded_and_leaves_the_unit_failed_until_restart` |
| One region ahead is repaired from the other on restart | nv | `test_a_cut_after_one_region_finished_is_repaired_from_it` |
| Damage anywhere but torn tail faults; split histories fault; gaps >1 fault | nv | `test_damage_anywhere_but_the_tail_and_split_histories_are_faults_not_guesses` |
| Stuck bit caught by read-back | nv | `test_a_stuck_bit_is_caught_by_the_read_back` |
| Keys written once | geu | `test_keys_are_written_once` |
| Gate closed by default; opens for one transaction on granted port | geu | `test_the_gate_is_closed_by_default_and_opens_for_one_transaction_on_the_granted_port` |
| Commitment expiring exactly now refused at request | geu | `test_a_commitment_that_expires_exactly_now_is_refused_at_the_request_not_later` |
| Grant dies with lease; second grant replaces first on that port | geu | `test_the_grant_dies_with_its_lease_and_a_second_grant_replaces_the_first_on_that_port` |
| Every refusal has its own reason and is written to chain | geu | `test_every_refusal_has_its_own_reason_and_is_written_to_the_chain` |
| Burn comes before gate; refused request burns nothing | geu | `test_the_burn_comes_before_the_gate_and_a_refused_request_burns_nothing` |
| Memory fault closes everything and stays closed | geu | `test_a_memory_fault_closes_everything_and_it_stays_closed` |
| Power cut before burn leaves approval unused; after burn leaves it spent | geu | `test_a_power_cut_before_the_burn_finished_leaves_the_approval_unused_and_after_it_leaves_it_spent` |
| Clock reading earlier than record makes unit refuse | geu | `test_a_clock_that_reads_earlier_than_the_record_makes_the_unit_refuse` |
| State survives restart (keys, burned, hard_stop, dma) | geu | `test_state_survives_a_restart` |
| Hard stop by anyone; restore only by human with correct commitment | geu | `test_a_hard_stop_by_anyone_and_a_restore_only_by_the_human` |
| Grant issued before hard stop cannot be used after | geu | `test_a_grant_issued_before_a_hard_stop_cannot_be_used_after_it` |
| DMA reaches port only through human-signed table | geu | `test_dma_reaches_a_port_only_through_the_table_the_human_signed` |
| Bypass write refused, recorded, trips stop (if configured) | geu | `test_a_write_that_skips_the_unit_is_refused_recorded_and_trips_the_stop` |
| Locking needs human commitment for exactly this workflow+steps | pre_unit | `test_locking_needs_a_human_commitment_for_exactly_this_workflow_and_steps` |
| Locked workflow runs in order; each result hash on chain first | pre_unit | `test_a_locked_workflow_runs_in_order_and_each_result_hash_is_on_the_chain_first` |
| Every deviation traps before anything runs | pre_unit | `test_every_deviation_traps_before_anything_runs` |
| Budgets, crashes, wrong outputs, non-bytes all trap and release nothing | pre_unit | `test_budgets_crashes_wrong_outputs_and_non_bytes_all_trap_and_release_nothing` |
| Unlocked workflow runs only in quarantine; gate refuses output | pre_unit | `test_an_unlocked_workflow_runs_only_in_quarantine_and_the_gate_refuses_its_output` |
| Accelerator output tainted unless locked hash vouches | pre_unit | `test_an_accelerators_output_is_tainted_unless_a_locked_hash_vouches_for_it` |
| Revocation needs own commitment; locks survive restart | pre_unit | `test_revocation_needs_its_own_commitment_and_locks_survive_a_restart` |
| Nothing runs while unit stopped or faulted | pre_unit | `test_nothing_runs_while_the_unit_is_stopped_or_faulted` |
| GEU and jacket decide alike on every vector | conformance | `test_the_hardware_model_and_the_software_jacket_decide_alike_on_every_vector` |
| Suite notices looser hardware (replay protection removed) | conformance | `test_the_suite_notices_a_hardware_model_that_is_looser_than_the_software` |
| Suite notices stricter hardware (human-only denied) | conformance | `test_the_suite_notices_a_hardware_model_that_is_stricter_than_the_software` |

### Non-guarantees

| Non-guarantee | Reason |
|---|---|
| No timing, power, area guarantees | Software reference model, not a circuit |
| No defense against physical attacker with probe | Design assumption: signing device out of reach |
| No enforcement against same-process code bypass | Python 'private' is convention |
| No expert-reviewed cryptography | Not independently security-reviewed |
| No hardware cycle/byte counting | PRE budget driven by harness `charge()` |
| No continuous clock rollback detection | Only at unit init |
| No guarantee denial records persist if append fails | Best-effort; denial still enforced |
| No native mobile builds | Pure Python; runs inside Python runtime only |

## 5. Failure modes

| Failure mode | What happens | Test |
|---|---|---|
| Tamper with NV region (middle record) | `NVFault` on init; unit refuses to start | `test_damage_anywhere_but_the_tail_and_split_histories_are_faults_not_guesses` |
| Missing commitment (no keys) | `Denied(no_keys)` on first request | `test_keys_are_written_once` |
| Expired commitment | `Denied(expired)` at request; nonce not burned | `test_a_commitment_that_expires_exactly_now_is_refused_at_the_request_not_later` |
| Replay (spent nonce) | `Denied(replay)`; burn not attempted | `test_every_refusal_has_its_own_reason_and_is_written_to_the_chain` |
| Corrupt record (hash mismatch) | `NVFault` on init; unit faults | `test_damage_anywhere_but_the_tail_and_split_histories_are_faults_not_guesses` |
| Power cut before burn | Approval unused; can be used after restart | `test_a_power_cut_before_the_burn_finished_leaves_the_approval_unused_and_after_it_leaves_it_spent` |
| Power cut after burn | Approval spent; replay denied on restart | `test_a_power_cut_before_the_burn_finished_leaves_the_approval_unused_and_after_it_leaves_it_spent` |
| Clock rollback | Unit faults on init; refuses all requests | `test_a_clock_that_reads_earlier_than_the_record_makes_the_unit_refuse` |
| Wrong action/params signed | `Denied(bad_signature)` or `Denied(bad_params)` | `test_every_refusal_has_its_own_reason_and_is_written_to_the_chain` |
| Wildcard/odd-spelled action | `Denied(wildcard)` or `Denied(odd_spelling)` | `test_every_refusal_has_its_own_reason_and_is_written_to_the_chain` |
| Budget exceeded in PRE step | `Trap(budget_exceeded:*)`; nothing released | `test_budgets_crashes_wrong_outputs_and_non_bytes_all_trap_and_release_nothing` |
| Code/input hash mismatch | `Trap(code_mismatch)` or `Trap(inputs_mismatch)`; step never runs | `test_every_deviation_traps_before_anything_runs` |
| Output hash mismatch | `Trap(output_mismatch)`; result not released | `test_budgets_crashes_wrong_outputs_and_non_bytes_all_trap_and_release_nothing` |
| Accelerator result no locked hash | Returns `Tainted`; gate refuses on `transact` | `test_an_accelerators_output_is_tainted_unless_a_locked_hash_vouches_for_it` |
| Unlocked workflow result | Returns `Quarantined`; gate refuses on `transact` | `test_an_unlocked_workflow_runs_only_in_quarantine_and_the_gate_refuses_its_output` |
| Hard stop engaged | All requests `Denied(hard_stop)`; grants cleared | `test_a_hard_stop_by_anyone_and_a_restore_only_by_the_human` |
| DMA initiator not in table | `Denied(dma_not_allowed)` | `test_dma_reaches_a_port_only_through_the_table_the_human_signed` |
| Bypass port write | `Denied(side_door)`; recorded; hard stop if configured | `test_a_write_that_skips_the_unit_is_refused_recorded_and_trips_the_stop` |

## 6. Dependencies and layer rules

Registry entry (verbatim):

```python
RegistryEntry(
    name="vega-chip-sdk",
    layer=14,
    requires=("vega-custody-sdk", "vega-governance-jacket-sdk"),
    provides=("nv", "geu", "pre_unit", "conformance"),
    status="BUILT",
)
```

Dependencies point **down layers only** (layer 0 custody, layer 1 jacket), never up or sideways. No cycles. This SDK owns exactly one concern: the governance hardware reference model.

## 7. Conformance

A third party can verify by running the test suite:

```bash
python -m pytest tests/ -v
# or
python -m unittest tests.redteam_1_chip -v
```

**Passing means:** all 34 tests pass; the GEU and software jacket decide identically on all conformance vectors; mutation suite kills 46/48 mutations (2 known survivors documented).

**Passing does NOT mean:** production readiness; expert-reviewed cryptography; physical security; timing/power/area correctness; hardware implementation exists (FPGA/silicon is DESIGNED ONLY); continuous clock rollback protection; defense against same-process bypass.