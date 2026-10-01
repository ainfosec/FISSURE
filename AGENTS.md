# FISSURE AI Development Guidance

This file contains repository-wide guidance for AI coding tools and agents working on FISSURE.

Keep this file concise. Detailed architectural intent, subsystem assumptions, plans, and validated lessons should live in the appropriate documentation rather than accumulating here.

## Before Making Changes

1. Read the relevant portions of `README.md`.
2. Search the repository for additional `AGENTS.md` files that apply to the files being modified.
3. Review relevant guidance under `docs/ai/` when present.
4. Review relevant active plans under `docs/plans/` when present.
5. Inspect the current implementation and nearby working examples before proposing or making changes.

Do not rely on documentation alone when the current source can answer a question about implementation behavior.

## Source of Truth

Use this order when gathering context:

`AGENTS.md` → relevant documentation and plans → canonical examples → current source code

Current source code is authoritative for existing behavior unless:

- the task explicitly requires changing that behavior, or
- an active design plan clearly describes an intentional migration away from it.

If documentation and implementation disagree, identify the discrepancy rather than silently choosing one.


## Task-Specific Guidance

Before making changes, read the guidance relevant to the task:

- System architecture, component boundaries, state ownership, and data flow: `docs/ai/architecture.md`
- Plugins, Actions, Operations, callbacks, hardware, flow graphs, and plugin lifecycle: `docs/ai/plugins.md`
- Active future-state designs and migrations: `docs/plans/README.md` and any relevant linked plan

Read multiple guidance files when a task crosses subsystem boundaries.

## Development Approach

Prefer changes that follow existing FISSURE architecture and patterns.

When adding capabilities:

- Prefer plugins, Actions, and Operations over modifications to FISSURE core when practical.
- Reuse existing framework services and messaging paths rather than creating parallel mechanisms.
- Inspect nearby working implementations before introducing new patterns.
- Preserve compatibility with distributed Sensor Node operation where applicable.
- Avoid broad refactors unless they are necessary for the requested change.

Do not assume that a locally working implementation is sufficient if the affected workflow also supports remote Sensor Nodes, plugins, TAK, artifacts, or distributed execution.

## Code Changes

- Make focused changes and avoid unrelated cleanup.
- Preserve existing decorators when replacing functions or methods.
- Preserve public interfaces unless the task explicitly requires changing them.
- Follow surrounding naming, formatting, callback, messaging, and error-handling conventions.
- Use two blank lines between top-level Python functions.
- Use one blank line between methods within classes.
- Keep short callback argument lists inline when practical.
- Do not introduce dependencies without a clear need.
- Do not duplicate functionality that already exists elsewhere in the framework.

## Validation

Before considering a change complete:

- Inspect the resulting diff.
- Check affected call sites and related workflows.
- Exercise the actual user-facing path when practical.
- Test local and remote behavior when the feature supports both.
- Check start, stop, cleanup, and error paths for long-running Operations.
- Verify that generated files, Artifacts, status messages, detections, map updates, or other outputs use established FISSURE mechanisms where applicable.

Do not claim hardware-dependent behavior was validated unless it was actually tested with the required hardware or data.

## Documentation and Plans

Use `docs/ai/` for information that is difficult to infer reliably from source code, such as:

- architectural intent
- subsystem assumptions
- framework contracts
- common failure modes
- validated development lessons
- non-obvious implementation conventions

Use `docs/plans/` for:

- active design work
- intended future behavior
- migrations
- architectural changes not yet fully represented in source code

Avoid duplicating straightforward code documentation that an agent can obtain by inspecting the implementation.

## Lessons Learned

Reusable observations from AI-assisted development should not automatically become authoritative guidance.

When an agent discovers a lesson that may be useful beyond the current task, it should call the lesson out clearly at the end of its work and suggest where the guidance would best belong.

Promote only lessons that are:

- generalizable beyond one bug or task
- still applicable to the current architecture
- difficult to infer from source alone
- useful for preventing repeated mistakes

After human review, accepted lessons can be added to the narrowest appropriate guidance, such as a subsystem-specific file under `docs/ai/` or, for truly repository-wide rules, this `AGENTS.md`.

Do not automatically modify `AGENTS.md` or other authoritative guidance based on lessons discovered during a task.