# Execution Context and Artifact Provenance

**Status:** Active

## Purpose

FISSURE should preserve enough execution context to explain where an Operation and its resulting Artifacts came from without mixing framework metadata into ordinary user parameters.

The intended design is hierarchical:

```text
Action execution
    -> one or more Operation executions
        -> Artifacts / Findings / other results
```

Each level should retain its own identity and parameters.

## Intended Model

Before launching child Operations, the framework should capture Action-level execution context and pass it to each Operation separately from the Operation's normal arguments.

Every Operation should receive an in-memory `execution_context` containing:

- parent plugin name
- parent plugin version
- parent Action name
- parent Action execution/run ID
- parent Action parameters
- Operation name
- Operation execution/run ID
- Operation parameters

Operation-level parameters remain distinct from Action-level parameters.

Do not flatten all Action and Operation parameters into one dictionary.

## Injection

Execution context should be injected by the framework rather than manually assembled inside each Operation.

The Action execution path should capture the parent context before launching child Operations.

The Sensor Node Operation runner should provide the context to the Operation separately from ordinary Operation arguments.

Operations should be able to use the context without requiring every plugin author to recreate provenance plumbing.

## Provenance Intent

The execution context is intended to support provenance for outputs such as:

- Artifacts
- Findings
- analysis results
- generated files
- derived data products
- other framework-managed results

Where appropriate, stored provenance should make it possible to determine:

- which plugin produced the result
- which plugin version was used
- which Action initiated the work
- which Action execution produced it
- which Operation produced it
- which Operation execution produced it
- which parameters were supplied at each level

## Runtime vs Persistence

The full `execution_context` may remain in memory during execution.

Persistent records should store the subset of provenance required to explain and reproduce the result without unnecessarily copying transient framework state.

Artifact and result schemas should evolve deliberately rather than blindly serializing the entire runtime context.

## Compatibility

Existing Actions and Operations should continue to work while provenance support is introduced.

Framework-level provenance injection should be additive where practical.

Avoid requiring every existing plugin to change solely to receive execution context.

If older Operations ignore `execution_context`, normal execution should continue.

## Architectural Boundaries

Execution context is framework metadata.

It should not be treated as:

- ordinary user parameters
- plugin-specific state
- Dashboard-only metadata
- a replacement for Operation IDs
- a replacement for Artifact metadata

The framework should own creation and propagation of execution context.

Plugins and Operations should consume it when useful but should not define incompatible provenance formats.

## Artifact Integration

Artifacts should eventually preserve enough provenance to connect them back to the Action and Operation executions that produced them.

The Artifact framework should be the preferred place to persist provenance for generated files and managed outputs.

Do not create plugin-specific provenance sidecar formats when the shared Artifact model can represent the information.

## Future Considerations

Areas that may need follow-on design include:

- schema for persisted provenance
- database storage for execution records
- relationships between Action runs, Operation runs, Artifacts, Findings, SOIs, and Targets
- UI presentation of provenance
- replay/reproduction of prior executions
- provenance for nested or chained Actions
- provenance across remote Sensor Nodes
- plugin/version identity when plugins are updated after an Artifact was created

## Guidance for AI Tools

Before modifying execution-context or provenance behavior:

1. Inspect the current Action launch path.
2. Inspect the Sensor Node Operation runner.
3. Inspect the `Operation` base class.
4. Inspect current Artifact creation and update paths.
5. Review any newer plans or schema changes that supersede this file.

Preserve the separation between parent Action context and Operation-specific parameters unless the design is intentionally changed.
