# Protocol Discovery: AI Development Guidance

This document guides AI-assisted development of FISSURE's **Signal Analysis > Protocol Discovery** workflow and database-backed packet identification. Read `AGENTS.md`, `docs/ai/architecture.md`, and the relevant current source before modifying this subsystem. **The checked-out source and database schema take precedence over examples here when they differ.**

## Purpose and boundaries

FISSURE should help an operator progress from an RF recording to reproducible, inspectable packet evidence, whether or not a known protocol definition exists. Keep these activities distinct:

1. **Demodulation:** Recover candidate symbol streams from actual IQ samples and known acquisition metadata.
2. **Bitstream & Framing:** Test encoding, polarity, timing and frame boundaries; preserve candidate provenance.
3. **Packet Analysis:** Compare recovered messages against predeclared format rules, show decoded fields and explain every candidate.
4. **Future investigation workflows:** Correlate findings with SOIs, managed Artifacts and eventually Sensor Node operations. Do not imply those end-to-end integrations already exist unless the current code demonstrates them.

The three interactive tabs are the current deliverable. Avoid broad PD/TSI refactors, generic protocol generation systems, or new distributed messaging paths while fixing their basic behavior.

## Relevant implementation

| Responsibility | Current source |
| --- | --- |
| Dashboard demodulation workflow, IQ/SigMF files, SOI/Artifact *source selection*, plots and controls | `fissure/Dashboard/Slots/TSITabSlots/pd_demodulation.py` |
| Dashboard framing workflow, candidate selection and handoff | `fissure/Dashboard/Slots/TSITabSlots/pd_bitstream_framing.py` |
| Dashboard message collection, candidate/evidence/field rendering | `fissure/Dashboard/Slots/TSITabSlots/pd_packet_analysis.py` |
| Signal processing, symbol estimation and recovery | `fissure/utils/protocol_demodulation.py` |
| Bit transformations, frame proposals and CRC *hypotheses* | `fissure/utils/protocol_framing.py` |
| Bit normalization and file/text reading | `fissure/utils/protocol_bitstream.py` |
| Packet input, cross-message observations and candidate orchestration | `fissure/utils/protocol_packet_analysis.py` |
| Declarative format validation and candidate evaluation | `fissure/utils/protocol_packet_formats.py` |
| Legacy/specialized validators and weak layout suggestions | `fissure/utils/protocol_packet_signatures.py` |
| Existing PostgreSQL Library cache | `fissure/utils/library.py`, HIPRFISR's current cache distribution path |

Keep analysis utilities **Qt-independent** so they can be reused outside the Dashboard later. Keep GUI state and rendering in Dashboard slots. Follow existing PyQt5 widget names and Light/Dark/Custom theme conventions. Do not rewrite complete existing files for small fixes.

## Library records are not interchangeable

- **`protocols`** stores protocol reference identities; existing modulation, frequency and SOI reference tables serve their established roles.
- **`packet_types`** stores legacy Packet Crafter packet layouts/defaults. Field names, widths and order can inform structure, but a matching total length is only **structural compatibility**. `Default Value`, `Is CRC`, and example payloads are **not** automatically verified signature or checksum definitions. Do not silently repurpose these records or duplicate their contents without a reason.
- **`packet_formats`** stores independently authored format-identification/validation profiles, in PostgreSQL with JSONB `definition` data. This is the authoritative runtime catalog for enabled declarative packet identification. An optional link to `protocols`/`packet_types` does **not** imply the legacy layout is authoritative for decoding.
- **Captured packets, bitstreams, IQ, evidence and results** are observations, not Library format definitions. Do not store recordings or packet histories inside `packet_formats`.

`cacheTableData()` loads enabled `packet_formats` into FISSURE's existing Library cache. The Qt-independent evaluator consumes cached rows; it does **not** query PostgreSQL for every message. The importer is a developer utility, not a separate runtime catalog. A source JSON file is an import/test artifact, not a required installed Library directory. The shipped PostgreSQL custom-format `.backup` must include the schema and approved definitions.

## Evidence, confidence and provenance

- **Observed:** Bit values, bit lengths, source filename, capture number, timing, acquisition metadata, symbol estimates and other measured properties.
- **Hypothesis:** Demodulation, encoding, polarity, frame boundaries, CRC candidates found during a framing search, or unknown packet structure. A hypothesized CRC does not independently validate a protocol.
- **Structural only:** Existing Packet Crafter layout lengths/fields happen to fit. Never present this as established identity.
- **Validated candidate:** A predeclared definition passes the applicable independent checks. Show which checks passed, failed, were not evaluated, and why.
- **Interpretation:** A documented mapping from bits to meaning, with source/reference; do not promote experimental names or guessed functions into protocol facts.

Keep the **Unidentified protocol** fallback and retain rejected alternatives for inspection. Do not assign invented probabilities or percentages. `Strong`, `Possible`, `Rejected`, `Structural only`, and `Unknown` are evidence-based classifications **within the current evaluator**, not guarantees of global identity. Definition `validation_status` (`draft`, `experimental`, `verified`) is distinct from a packet's match strength.

Preserve exact bit length, bit order and zero-based `[start, end)` offsets. A 66-bit TPMS message carried in nine hexadecimal octets includes six padding bits; do not silently interpret it as a 72-bit packet. For partial-nibble fields, numeric hex must not be generated by right-padding bits. Reject attempts to trim nonzero trailing bits without explicit reconciliation.

## Declarative packet-format capabilities (schema version 1)

**Check the actual `SUPPORTED_RULES`, `validate_definition()` and `validate_format_record()` first.** The current evaluator supports:

- Length: `exact_bits`, or bounded `min_bits` / `max_bits`.
- Fields: named, bounded bit spans with `start` **or** `from_end_bits`; render modes `hex`, `integer`, `binary`, `linear`, `check_status`.
- Checks: `complement`, `crc`, `range`, `fixed_bits` (including masks), `frame_length`, and `counted_pairs`.
- Evidence categories: `identity` versus `plausibility`.
- Match policy: `candidate_any`, `strong_all`, `reject_on_failure`.
- Optional signal context: modulation hints are compatibility information, not stand-alone identity evidence.

`counted_pairs` checks length/count relationships; it does **not** currently expand repeated component groups into individual decoded rows. Do not invent unsupported rule types, arbitrary Python expressions, a complete protocol parser, or nested/conditional structures in JSON and assume the engine will understand them. If a protocol needs another generic capability, describe the gap, a reusable interface, and regression examples **before** implementing it.

Definitions are bounded in size and complexity; see the constants and validators in `protocol_packet_formats.py`. Use stable `format_key` values and increment `revision` when an imported definition changes. Keep schema version separate from per-format revision. Store a real reference, honest scope, and notes about uncertainties.

## AI-assisted procedure to add a packet format

1. **Inspect** the relevant `protocols`, `packet_types`, existing formats and source code. Record what the Library already knows and which details are only crafting defaults.
2. **Collect evidence:** retain original IQ/packet bits, exact sample format/rate/frequency when known, preprocessing parameters, frame boundaries, timing, and multiple packets when available. Separate positive examples, negative examples, independent references and assumptions.
3. **Define the intended scope** before coding: protocol family versus a particular frame class, manufacturer variant, command, or physical-layer representation. Do not make observed device IDs or one experiment's command labels universal requirements.
4. **Write a versioned, declarative definition** using only supported schema rules. Prefer reusable checks over a new protocol-specific Python function. Identity checks should be justified independently of the sample being fitted.
5. **Validate locally** from the repository root with `python3 Tools/import_packet_formats.py /path/to/definition.json`. This does not modify PostgreSQL. Use the current importer usage if its interface changes.
6. **Test acceptance and rejection** with independent packets, corruptions, wrong lengths, different IDs/commands and unrelated traffic. Confirm both the Evidence table and decoded Fields, not merely the top candidate title. A malformed packet must not remain Strong through a failed required check.
7. **Import only after review** using the same command with `--apply`. The importer writes to PostgreSQL and refuses changed content at the same revision. Refresh the HIPRFISR/Dashboard Library cache and confirm `Format provenance` (key, revision, SHA-256 digest).
8. **Ship it:** update and verify `db/fissure_db_dump.backup` plus all installer references. A profile that works only in the developer's local database is not a distributed feature.

Avoid making automatic database changes, changing legacy packet definitions, or labeling a definition `verified` solely because it passes schema validation or one capture. AI can propose and prepare definitions and evidence; a maintainer decides what is imported and shipped.

## Known regression cases and scope

| Input | What must be checked | Important limitation |
| --- | --- | --- |
| TPMS 315 MHz capture | 66-bit message, expected complement, CRC-8, pressure/temperature conversions, corrupted CRC rejected | Validates the documented `gr-tpms_poore` profile, **not all TPMS** |
| Z-Wave 916 MHz Color Switch captures | 2-FSK hypothesis, extracted 200-bit delimiter+MAC or 192-bit MAC-only candidate, frame length, command, count, CRC-16, different Home IDs | Color Switch Set is **not** arbitrary Z-Wave coverage; Auto on long multi-burst captures requires caution |
| X10 OOK sample | Pulse-distance decoding to 32 bits, two complement pairs, reserved-bit rules, corrupted pairs rejected | No assertion of a specific house/unit/function unless a documented mapping was applied |
| Unknown or unrelated bitstream | Data preserved, identification stays Unknown unless predeclared evidence passes; unrelated length-only layouts remain structural suggestions | Do not overfit to make every packet identifiable |

Test the complete user path where possible: **IQ import -> Demodulation -> Bitstream & Framing -> Open Selected/All -> Packet Analysis -> Analyze Checked -> Evidence/Fields**. Verify multi-message selection, duplicate imports, bad input, candidate switching, deleting the active row, and reanalysis. Check at least one known OOK and one known FSK capture after modifying Auto selection. Large/idle-heavy IQ captures need performance checks; numerous proposed frames do not imply numerous validated packets.

## Code and documentation changes

- Work from the user's latest working source. Read any narrower `AGENTS.md` and active plan. Do not base a patch only on older chat snippets or an earlier archive.
- For existing source, provide **one raw text change file** with the filename and exact Ctrl+F anchor immediately before each **complete function replacement**, not scattered fragment edits. New files may be provided whole. Preserve decorators, function interfaces, module imports, and the slot-module `import inspect` / `__all__` convention.
- Explain Qt Designer layout changes separately so the maintainer can apply them; keep CSS adjustments targeted and theme-consistent.
- Test syntax, relevant algorithms and positive/negative fixtures. Explicitly distinguish offline tests from a live GUI, database, SDR, distributed, or installer test.
- Put stable intent and non-obvious contracts in `docs/ai/`; place future designs in `docs/plans/`. Do not automatically promote one-off lessons into `AGENTS.md`.

## Deferred until separately requested

Automated packet-format generation, an extensive format editor, generic nested/repeated-field rendering, persistent Packet Analysis sessions, durable SOI identification histories, packet-analysis artifact exports, Sensor Node format-bundle deployment, auto-updating SOI identities, larger-capture segmentation, and legacy PD/TSI removal are not assumed complete by these instructions. Treat them as future work and verify current implementation before updating this list.
