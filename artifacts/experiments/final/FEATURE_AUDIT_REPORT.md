# Feature audit — candidates for low-intensity C2 detection

Read-only audit. **No feature was selected, no model was trained, no dataset was
modified, no PostgreSQL statement was issued.** This document records what is
available and what each candidate risks. Choosing features is a separate decision.

## Scope and method

Candidates are restricted to quantities derivable by aggregation over the events
already persisted in `m4_canonical.flow_end_events` and
`mb4_canonical.flow_end_events`, grouped into the **same** 60-second windows and
the same entity key that M6 and MB6 use. Reconstruction was validated against the
frozen evidence before any measurement: **376 attack windows, 70 578 benign
windows, 177 botnet windows** — exact matches.

Three populations are reported separately, because the botnet column is the one
that matters: it is the 47.1% of positives the current features cannot see.

**A perfect separation is treated as a leakage warning, not as merit.** The primary
screen is whether a candidate's attack range and benign range are disjoint. **All
seventeen candidates pass that screen** — none is a perfect separator.

## Measurements

| Candidate | Miss. attack | Miss. benign | Miss. botnet | Median attack | Median benign | **Median botnet** | Distinct (benign) | Range disjoint |
|---|---|---|---|---|---|---|---|---|
`duration_mean` | 0.0000 | 0.0000 | 0.0000 | 0.5822 | 5.8680 | **0.0828** | 67 197 | no |
`duration_max` | 0.0000 | 0.0000 | 0.0000 | 9.2911 | 6.0911 | **0.0935** | 66 732 | no |
`duration_sum` | 0.0000 | 0.0000 | 0.0000 | 29.8098 | 11.0083 | **0.3844** | 67 141 | no |
`duration_cv` | 0.1676 | 0.5867 | 0.3107 | 0.1617 | 0.2901 | 0.2834 | 29 040 | no |
`interarrival_mean` | 0.1676 | 0.5867 | 0.3107 | 1.2340 | 0.1671 | **8.4978** | 23 600 | no |
`interarrival_stdev` | 0.2181 | 0.7906 | 0.4181 | 1.2679 | 0.5282 | **3.6006** | 14 390 | no |
`interarrival_cv` | 0.2181 | 0.7906 | 0.4181 | 1.1008 | 1.1543 | **0.4250** | 14 742 | no |
`bytes_per_packet_source` | 0.0000 | 0.0012 | 0.0000 | 39.0000 | 52.9444 | 39.2000 | 29 238 | no |
`bytes_per_packet_destination` | 0.0000 | 0.0354 | 0.0000 | 32.0000 | 232.2910 | **32.0000** | 33 976 | no |
`byte_direction_ratio` | 0.0000 | 0.0758 | 0.0000 | 0.6025 | 0.2731 | **0.6049** | 40 976 | no |
`packet_direction_ratio` | 0.0000 | 0.0000 | 0.0000 | 0.5532 | 0.5205 | 0.5556 | 5 566 | no |
`packet_asymmetry` | 0.0000 | 0.0000 | 0.0000 | 50.0000 | 2.0000 | 5.0000 | 574 | no |
`distinct_source_ports` | 0.0000 | 0.0000 | 0.0000 | 16.5000 | 1.0000 | 5.0000 | 393 | no |
`distinct_conversations` | 0.0000 | 0.0000 | 0.0000 | 17.0000 | 1.0000 | 5.0000 | 400 | no |
`distinct_connection_states` | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 1.0000 | 1.0000 | 3 | no |
`zero_response_fraction` | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 27 | no |
`empty_flow_fraction` | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 6 | no |

`connection_state` inventory, event counts:

| Population | States |
|---|---|
attack | `RSTO` 195 351 · `SF` 66 042 · `S1` 127 · `S0` 114 · `RSTR` 25 · `REJ` 1 · `S3` 1 · `OTH` 1 |
**botnet** | **`SF` 736 — a single state, 100%** |
benign | `SF` 353 862 · `RSTR` 5 126 · `RSTO` 2 932 · `S0` 2 840 · `REJ` 945 · `S1` 349 · `SH` 278 · `OTH` 276 · `S3` 252 · `SHR` 221 |

---

## Per-candidate verdicts

### `duration_mean`, `duration_max`, `duration_sum`

**Definition** mean, maximum and sum of `event_duration` over the window's events.
**Source** `flow_end_events.event_duration`, exact `NUMERIC(38,22)`.
**Availability** both populations, **zero missingness**.
**Variability** 67 197 distinct benign values — no degeneracy.
**Separation** botnet median 0.0828 s against benign 5.868 s, a 71× gap in the
direction the current features cannot express. Ranges overlap.
**Leakage risk — identity** none: duration encodes no address, port or service.
**Leakage risk — day/capture** none observed; durations are flow properties.
**Leakage risk — label** ⚠️ **minor, and label-induced.** MB-LABEL assigns
`ambiguous` to events whose exact interval crosses the M5 rule boundary, and those
127 windows were excluded from the benign population. The benign class is therefore
slightly depleted of very-long-duration flows near the day's edges — 127 of 70 705,
**0.18%**. Small, but it is a selection effect created by the label, not by the
traffic, and it must be recorded.
**Online availability** ⚠️ **offline-only assumption.** `duration` exists only once
a flow has ended. Every row in this evidence is a completed `FlowEnd`, so duration
is always present here. A real online detector at window close would see flows still
open and would have no duration for them. This is the most serious operational
caveat in the audit.
**Verdict** **VALID for offline benchmarking, CONDITIONAL for online use.** Strong
candidate for the botnet gap. Requires an explicit statement that the benchmark
assumes completed flows.

### `interarrival_mean`, `interarrival_stdev`, `interarrival_cv`

**Definition** mean, standard deviation and coefficient of variation of the gaps
between consecutive `event_start_time` values within the window.
**Source** `flow_end_events.event_start_time`.
**Availability** ⚠️ **undefined for single-event windows.** Benign missingness
0.5867 for the mean and **0.7906** for the dispersion measures; botnet 0.3107 and
0.4181.
**Variability** 14 390 to 23 600 distinct benign values.
**Separation** the strongest signal in the audit for the botnet: `interarrival_mean`
botnet 8.4978 s against benign 0.1671 s, a 51× gap; and `interarrival_cv` botnet
**0.4250** against benign 1.1543, i.e. **markedly more regular** — the textbook
beaconing signature.
**Leakage risk — identity** none.
**Leakage risk — day/capture** none observed. The features use *differences* of
timestamps, never absolute time, so they cannot encode the day. This must be
enforced by construction if they are ever adopted.
**Leakage risk — missingness pattern** ⚠️ availability is a deterministic function
of `event_count >= 2`, and `event_count` is already an admitted feature. An
imputation indicator would therefore re-express information the model already has;
it introduces no *new* leakage but it must not be presented as an independent
signal.
**Online availability** computable at window close from start times alone, so
better than duration in that respect — but it inherits the same caveat if the
window's event set is incomplete.
**Verdict** **VALID, with a mandatory missing-value policy.** The highest-value
candidates for the botnet gap and the only ones that express periodicity. Cannot be
used without deciding, explicitly, how ~59% missing benign values are handled.

### `bytes_per_packet_destination`

**Definition** `destination_bytes / destination_packets` over the window.
**Availability** benign missingness 0.0354 where no packet returns.
**Separation** botnet 32.0 against benign 232.29, a 7× gap. Ranges overlap.
**Leakage risk** no identity, no day. Payload size per packet is a behavioural
property.
**Online availability** yes, from counters available at window close.
**Verdict** **VALID.** Moderate signal, low risk, small missingness.

### `byte_direction_ratio`, `packet_direction_ratio`

**Definition** `source_bytes / (source_bytes + destination_bytes)` and the packet
analogue.
**Separation** `byte_direction_ratio` botnet 0.6049 against benign 0.2731: the
botnet uploads more than it downloads, benign does the opposite. The packet ratio
barely separates (0.5556 vs 0.5205).
**Leakage risk — identity** ⚠️ **indirect.** "Source" and "destination" are defined
by the entity key's ordering, which is the connection originator. The ratio encodes
*directionality*, which is behavioural, but it inherits the originator convention.
It does not encode *which* host, so it is not host-identity leakage.
**Online availability** yes.
**Verdict** `byte_direction_ratio` **VALID**; `packet_direction_ratio`
**VALID but likely uninformative** — a 0.03 median gap.

### `packet_asymmetry`

**Definition** `abs(source_packets - destination_packets)`.
**Separation** attack 50 against benign 2, botnet 5.
**Leakage risk** none for identity or day. ⚠️ **strongly correlated with the
existing volume features** — it is a difference of two admitted features and adds
no new axis of information.
**Verdict** **VALID but redundant.** Not recommended: it re-expresses volume.

### `distinct_source_ports`, `distinct_conversations`

**Definition** count of distinct ephemeral source ports, and of distinct Zeek
`uid` values, in the window.
**Separation** botnet 5.0 against benign 1.0.
**Leakage risk — identity** ⚠️ `distinct_source_ports` counts **ephemeral** ports,
which are behavioural rather than identifying; it is not the destination port, which
was excluded because its attack range was exactly [1,1].
**Redundancy** ⚠️ **severe.** Each conn.log record carries a unique `uid` and
usually a unique ephemeral port, so both candidates are near-duplicates of
`event_count`, which is already admitted. Benign medians of 1.0 against an
`event_count` benign median of 1.0 confirm the collinearity.
**Verdict** **INVALID as new information.** Not leakage, but near-duplicates of an
existing feature. Adopting them would inflate the feature count without adding an
axis.

### `distinct_connection_states`

**Separation** median 1.0 in all three populations, only **3 distinct benign
values**.
**Verdict** **INVALID — near-degenerate.** Same failure mode as
`distinct_destination_ips` and `distinct_source_ips` in the current budget.

### `zero_response_fraction`, `empty_flow_fraction`

**Separation** median 0.0 in all three populations; 27 and 6 distinct benign values.
**Verdict** **INVALID — near-degenerate on this evidence.** They would matter for
scanning behaviour, which this dataset's attack set does not contain.

### Per-state fractions of `connection_state` — **NOT MEASURED, flagged**

The inventory shows `RSTO` dominating the attack events (195 351) while the botnet
is **100% `SF`** and benign is 84% `SF` with a long tail. A per-state fraction
feature such as `fraction_RSTO` would very likely separate the volumetric attacks
sharply.

**It was deliberately not evaluated as a candidate**, for a reason that must be
recorded: `RSTO` concentration is a property of the four volumetric attacks that
all originate from the **single host pair** `172.16.0.1 → 192.168.10.50`. Under R11,
a feature that keys on that behaviour cannot be distinguished from a feature that
keys on that host pair. Adding it would risk manufacturing exactly the host-pair
memorisation this project has been careful to avoid, and it would do nothing for
the botnet, which shows a single state.

**Verdict** **NEEDS REVIEW — deferred.** Not invalid in principle; unassessable
under R11 with this evidence.

---

## Summary table

| Candidate | Verdict | Reason |
|---|---|---|
`duration_mean` | **VALID** (offline) | 71× botnet gap, zero missingness, no identity or day encoding; assumes completed flows |
`duration_max` | **VALID** (offline) | as above |
`duration_sum` | **VALID** (offline) | as above; partly overlaps `duration_mean` × `event_count` |
`duration_cv` | **VALID** | dispersion of duration; 58.7% benign missing |
`interarrival_mean` | **VALID** | 51× botnet gap; 58.7% benign missing; requires missing-value policy |
`interarrival_stdev` | **VALID** | 79.1% benign missing |
`interarrival_cv` | **VALID** | beaconing regularity, botnet 0.425 vs benign 1.154; 79.1% benign missing |
`bytes_per_packet_destination` | **VALID** | 7× botnet gap, 3.5% missing |
`bytes_per_packet_source` | **VALID but weak** | 39.0 vs 52.9, small gap |
`byte_direction_ratio` | **VALID** | botnet 0.605 vs benign 0.273 |
`packet_direction_ratio` | **VALID but uninformative** | 0.03 median gap |
`packet_asymmetry` | **REDUNDANT** | difference of two admitted features |
`distinct_source_ports` | **INVALID** | near-duplicate of `event_count` |
`distinct_conversations` | **INVALID** | near-duplicate of `event_count` |
`distinct_connection_states` | **INVALID** | near-degenerate, 3 distinct benign values |
`zero_response_fraction` | **INVALID** | near-degenerate on this evidence |
`empty_flow_fraction` | **INVALID** | near-degenerate on this evidence |
per-state `connection_state` fractions | **NEEDS REVIEW** | unassessable under R11; would key on one host pair |

## Cross-cutting risks that apply to any adoption

1. **The completed-flow assumption.** Duration and inter-arrival both presume the
   window's flows have ended. Every row here is a `FlowEnd`, so the assumption holds
   in this evidence and fails for a real online detector. Any adopted feature set
   must state this explicitly.
2. **Missingness is not random.** Inter-arrival availability is exactly
   `event_count >= 2`. 58.7% of benign windows and 58.6% of M6 windows are
   single-event. A missing-value policy is mandatory and must not be allowed to
   smuggle `event_count` back in as a second copy.
3. **A 0.18% label-induced selection effect on duration.** The 127 `ambiguous`
   windows excluded from the benign class were excluded *because* their flows crossed
   a time boundary, which correlates with long duration.
4. **R11 is unchanged and still binding.** No feature can create attack diversity.
   Even if the botnet becomes detectable, the conclusion would rest on 5 entities
   and 5 host pairs for that one type.
5. **No candidate separates the classes perfectly**, which is the one reassuring
   result: the audit found no new leakage channel of the kind that disqualified
   `entity_service`, `entity_transport` and `distinct_destination_ports`.

## Artifacts

`feature_audit_raw.json` — full per-candidate measurements for the three
populations, written alongside this report.
