# FISSURE Development Plans

This directory contains active design plans, architectural migrations, and intended future behavior that may not yet be fully represented in the current source code.

AI tools and developers should review relevant plans before making changes to affected subsystems.

Plans are not necessarily descriptions of current behavior. Current source code remains authoritative for implemented behavior unless a plan explicitly describes an intended migration or the task requires implementing that plan.

## Plan Status

Plans should indicate their current status when practical:

- **Active** - Intended work or architecture that is still being pursued
- **Implemented** - The planned behavior has been incorporated into the codebase
- **Superseded** - Replaced by a newer design or direction
- **Paused** - Not currently being pursued but retained for context

## Active Plans

- [Execution Context and Artifact Provenance](./execution_context_provenance.md)

Additional plans may be added for:

- plugin and Action architecture changes
- distributed Sensor Node behavior
- TAK integration
- deployment and packaging
- AI/ML integration
- UI and workflow migrations

## Guidance

Keep plans focused on intended behavior, design decisions, assumptions, and migration direction.

Do not duplicate implementation details that are easier to understand from the source code.

When a plan is completed or replaced, update its status rather than leaving ambiguous future-state guidance in place.
