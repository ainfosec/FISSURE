# FISSURE Plugin Development Guidance

This document captures FISSURE-specific plugin conventions, architectural intent, and recurring lessons that are easy to miss by reading one plugin in isolation.

Use this together with the repository-level `AGENTS.md`. Before changing a plugin, inspect the current plugin framework and several nearby working examples. Do not treat newly generated or unreviewed plugin code as canonical merely because it exists in `Plugins/`.

## Guiding Principle

A FISSURE plugin should add capability without creating a parallel framework.

Prefer the existing Action, Operation, Sensor Node, callback, artifact, hardware, and lifecycle mechanisms. Add new core behavior only when the capability is genuinely reusable across plugins and the framework does not already provide an appropriate mechanism.

Plugin-specific behavior should remain plugin-owned whenever practical.

## Plugin Layout

Plugins run directly from:

```text
Plugins/<PluginName>/
```

A normal plugin may contain:

```text
Plugins/<PluginName>/
├── actions.py
├── plugin.yaml
├── setup.py
├── operations/
├── scripts/
├── resources/
└── flow_graphs/
```

Use the directories according to their purpose:

- `actions.py` - Action exposure only: plugin name, tags, hardware compatibility, schemas, delegated-action registration, and thin calls into Operations.
- `operations/` - FISSURE-launched Operation implementations.
- `scripts/` - Helper executables, supporting Python modules, and custom libraries imported or called by Operations.
- `resources/` - Passive plugin-owned data such as models, lookup tables, templates, and static files.
- `flow_graphs/` - GNU Radio flow graphs and generated Python, normally organized by workflow and GNU Radio maintenance version.
- `plugin.yaml` - Plugin manifest and lightweight lifecycle metadata.
- `setup.py` - Plugin-owned external setup hook. Keep it inert by default.

Do not create alternate install trees or copy normal plugin code into system locations merely to make a plugin run. Resolve files relative to the plugin directory.

## `actions.py` Must Stay Thin

`actions.py` is an exposure and routing layer, not an implementation module.

It should contain only the pieces needed to expose Actions to FISSURE:

- `PLUGIN_NAME`
- `ACTION_TAGS`
- `ACTION_HARDWARE` when hardware restrictions are required
- `<action_name>_schema` definitions
- delegated-action declarations when applicable
- the async Action functions that launch Operations

Do not add general helper functions, parsing logic, protocol logic, hardware-selection logic, subprocess management, reusable utilities, or business logic to `actions.py`.

If logic is specific to one Operation, put it in that Operation. If several Operations in the plugin need it, put it under `scripts/` as a plugin-owned helper/library. If it is genuinely framework-wide behavior, consider a focused FISSURE core change instead.

FISSURE dynamically discovers module-defined async functions in `actions.py` as Actions. Extra async helpers can therefore accidentally become user-visible Actions. Keep the file intentionally simple even when a helper would technically work there.

### Normal Action Shape

A normal Action should:

1. expose its user-facing schema;
2. declare tags and required hardware when applicable;
3. perform only minimal Action-level parameter preparation;
4. call `component.run_plugin_operation(...)`.

Typical shape:

```python
async def example_action(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"Example action with parameters: {parameters}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "example_action.py",
        parameters,
        node_uid,
    )
```

Do not create a second execution/lifecycle mechanism inside an Action.

## Action Schemas

Action schemas are named:

```text
<action_name>_schema
```

and normally contain a `params` list.

Schema parameter names should line up with the Operation inputs they ultimately control. Expose meaningful user-configurable choices rather than every value an Operation happens to accept. Internal batching, refresh, retry, throttling, calibration, and implementation-tuning values should normally remain Operation defaults unless the task or workflow gives the user a clear reason to control them.

For radio hardware, frequency and gain are commonly useful operator-facing controls. Channel and antenna selection are also appropriate when the protocol or selected hardware presents real choices. Other low-level radio settings should normally be set to sensible Operation defaults and changed there when needed rather than exposed automatically. If a protocol may operate on multiple frequencies or channels and the Action monitors only one at a time, expose the relevant selector so the user can choose what to monitor.

Avoid unnecessary Dashboard-specific parameter translation. Prefer schema-driven Actions that can execute through the normal plugin path.

Choose schema types and display precision deliberately. Use integer types for genuinely bounded integer values. For large integer-like values such as sample rates or RF frequencies that may exceed a normal Qt integer widget range, prefer a numeric parameter with an explicit integer-like presentation such as `decimals: 0`, plus appropriate `min`, `max`, and `step`. Do not rely on generic default precision when it makes operator controls misleading or unnecessarily noisy.

Framework-supplied execution inputs are not user-facing schema parameters. Do not expose active evidence paths, Operation IDs, Inspection context, provenance context, or similar framework values merely because the Operation needs them.

If an Operation intentionally accepts one nested `parameters` dictionary, the Action may wrap the values for that constructor. Otherwise prefer passing the Action parameters directly.

### Keep User-Facing Scope Intentional

Do not create extra user-facing Actions, replay modes, file-analysis paths, sample-data workflows, or other capabilities merely because they are convenient for development or testing. Implement the capability the user requested and keep validation helpers internal when they do not represent an intended operator workflow.

Tests may use fixtures, prerecorded data, mock inputs, helper Operations, or support scripts without exposing those mechanisms as Actions.

If file replay, offline analysis, inspection, demodulation, or similar functionality is explicitly requested, place it in the workflow that matches its purpose rather than automatically tagging it as Tactical. Follow existing FISSURE workflow and tagging patterns.

## Action Tags

Use `ACTION_TAGS` to describe workflow membership and capability.

Tags should follow existing FISSURE conventions rather than inventing near-duplicate namespaces.

Reserved context tags have execution consequences:

- `client.dashboard`
- `client.tak`
- `node.local`
- `node.remote`

Absence of a `client.*` namespace is permissive. Absence of a `node.*` namespace is also permissive.

Only add client or node restrictions when the Action truly cannot work in the other context. Do not accidentally make a generally useful Action local-only or Dashboard-only.

Keep plugin-specific workflow metadata with the plugin instead of creating a new central configuration dumping ground.

## Inspection Actions

Inspection Actions operate on evidence already selected by the Dashboard. Treat the Inspection workflow as an existing framework contract rather than rebuilding file selection or result handling inside the plugin.

For an Action tagged for Inspection:

- use the active `_fissure_inspection_context` supplied in Action parameters for the selected evidence path and available metadata such as sample rate, center frequency, data type, and selected range;
- do not add a redundant user-facing `Input File` parameter when Inspection already owns the active evidence;
- use Inspection metadata when present and expose only meaningful fallbacks the operator may need to provide when metadata is absent;
- preserve the framework-provided `operation_id` through the Action and Operation when one is supplied;
- return structured analysis through the existing `inspection_callback` path;
- let the Dashboard turn an Inspection result into an editable Finding rather than inventing a plugin-specific Finding transport.

The Dashboard correlates an Inspection run with its Operation ID. Do not generate a second unrelated ID after the Dashboard has supplied one. The same correlated Operation ID must be used by the Sensor Node Operation, final Inspection callback, Stop path, and Operation-scoped outputs.

Follow the current canonical Inspection Action/Operation pattern for launch behavior. Do not add synchronous waiting or a parallel completion protocol unless the existing workflow explicitly requires it. Completion should arrive through the normal Inspection callback with the correct final state.

Inspection evidence may be waveform data, tabular data, or another supported representation. Keep representation-specific analysis in the plugin. Do not force core Inspection to treat every file as IQ, and do not assume an unobservable property is false merely because that representation cannot measure it.

## Hardware Compatibility

Use `ACTION_HARDWARE` only when an Action requires particular configured hardware.

Hardware names must match the exact FISSURE hardware type names used by Sensor Node configuration. Do not invent aliases or maintain duplicate global hardware-name mappings inside `actions.py`.

`ACTION_HARDWARE` controls Action availability. Runtime hardware-to-implementation selection belongs in the Operation.

If an Operation supports different flow graphs or implementations by hardware type or GNU Radio version:

- resolve that mapping in the Operation;
- use the exact FISSURE hardware type;
- use the current library/GNU Radio maintenance version where applicable;
- fail clearly when the selected combination is not actually available.

Do not advertise a hardware/version combination merely because an empty directory or placeholder exists.

### Runtime Resource Claims

`ACTION_HARDWARE` and `OperationMain.get_resources()` are different mechanisms.

- `ACTION_HARDWARE` filters whether the Action is offered for configured hardware.
- `get_resources()` describes runtime resources that must be allocated/locked by the Operation framework.

Use each for its intended purpose.

## Operations

Executable plugin Operations live under:

```text
Plugins/<PluginName>/operations/
```

The normal entry point is:

```python
class OperationMain(Operation):
```

The Sensor Node runner imports the file, creates `OperationMain`, injects supported framework callbacks/context based on the constructor signature, runs setup, registers the Operation, starts it, handles Stop requests, performs teardown, and removes it from the active-operation registry.

Do not duplicate that lifecycle inside plugin code.

### Operation Constructors

Operation constructors should:

- accept the user parameters needed by the Operation;
- normalize values that may arrive as strings;
- accept only the standard framework callbacks/services they use;
- call `super().__init__(...)` with those framework values;
- keep plugin-specific state on the Operation instance.

The Sensor Node runner filters supplied values against the constructor signature. If a callback or framework service is needed, declare the existing supported constructor argument rather than inventing a new plumbing path.

Standard framework inputs currently include:

- `node_uid`
- `logger`
- `alert_callback`
- `tak_cot_callback`
- `detection_callback`
- `status_callback`
- `target_callback`
- `soi_callback`
- `recommendation_callback`
- `inspection_callback`
- `position_callback`
- `artifact_manager`

Inspect the current `Operation` base class and Sensor Node runner for the authoritative list and current callback behavior.

## Use Existing Callback Mechanisms

When an Operation needs to return information to FISSURE, use the built-in callback that already represents that type of information.

Examples include:

- alerts -> `alert_callback`
- detections -> `detection_callback`
- status/progress -> `status_callback`
- Targets -> `target_callback`
- SOIs -> `soi_callback`
- recommended follow-on Actions -> `recommendation_callback`
- inspection/analysis results -> `inspection_callback`
- Sensor Node position -> `position_callback`
- custom TAK CoT only when a higher-level FISSURE data type is not the right representation -> `tak_cot_callback`

Do not invent one-off callbacks or direct Dashboard/HIPRFISR messages inside a plugin simply because it is convenient.

If a genuinely new recurring data type needs framework transport, treat that as a separate framework design change and add the generic mechanism in FISSURE core.

### Payload Shapes

Copy the current canonical payload shape for the callback being used. Do not create a similar-looking but incompatible dictionary.

For structured detections, inspect current detector Operations. Common fields include context such as:

- `kind`
- `event_type`
- `node_uid`
- `source_id`
- `opid`
- `timestamp`
- detector-specific measurements and metadata

Use the fields expected by the current core path rather than inventing plugin-only equivalents.

For callbacks used in loops or high-rate processing, avoid allowing a stalled callback to block the Operation indefinitely. Follow current Operations that use bounded waits where appropriate, and preserve `asyncio.CancelledError`.

## Location and Position

If an Operation needs the Sensor Node's current position, use the injected `position_callback`.

Do not create an independent GPS/gpsd polling implementation inside each plugin. The Sensor Node owns position acquisition and caching.

If a detection or Target has its own true location, such as a remote emitter or reported object position, preserve that object location rather than substituting the Sensor Node position.

Preserve accuracy, uncertainty, confidence, or similar quality values when they are supplied by the source or can be legitimately derived. Do not invent values merely to populate optional fields or make a map visualization appear more complete. For example, do not draw an uncertainty circle unless its radius represents actual source information or a defensible calculation.

## Artifacts and Generated Files

Use the existing Artifact framework for files/results that should become FISSURE Artifacts.

Prefer the helpers provided by the `Operation` base class, such as:

- `create_artifact(...)`
- `update_artifact(...)`

or the injected `artifact_manager` when an existing required workflow is not covered by those helpers.

Do not invent a second artifact registry, ad hoc file-transfer protocol, or callback just to return files.

Runtime Artifact files must be created inside the Operation's managed Artifact storage before they are registered. Do not write a result beside the input file, into the plugin directory, or into an arbitrary temporary/output directory and then pass that path to `create_artifact(...)`. Use the current `ArtifactManager` / `Operation` helpers to obtain the Operation-managed files directory and create the files there. Artifact path validation is intentional.

Keep the Operation ID used for managed Artifact storage aligned with the correlated Operation ID used by the workflow. Creating output under one Operation ID while returning results under another breaks lifecycle and provenance expectations.

Generated files that are implementation support rather than runtime results belong in plugin-owned `scripts/`, `resources/`, or `flow_graphs/` as appropriate.

## Supplemental Scripts and Libraries

Operations may call or import plugin-owned support code from `scripts/`.

Use this for:

- helper executables;
- custom Python libraries;
- parsing/formatting libraries shared by several Operations in the same plugin;
- supporting tools that are part of the plugin itself.

Resolve support paths relative to the plugin root. Do not assume the current working directory and do not require helper modules to be installed globally just so the plugin can import them.

Passive data, models, tables, and templates belong in `resources/`, not `scripts/`.

## GNU Radio Flow Graphs

Keep plugin-owned GNU Radio flow graphs under `flow_graphs/`.

### Directory Structure

FISSURE installation and flow-graph compilation logic relies on established directory names and version layouts when scanning plugin flow graphs. Do not invent a new layout when an existing flow-graph category fits the capability.

For hardware-specific flow graphs, prefer the established structure:

```text
Plugins/<PluginName>/flow_graphs/
└── <flow_graph_category>/
    ├── maint-3.8/
    │   └── <hardware>/
    │       ├── <flow_graph>.grc
    │       └── <flow_graph>.py
    └── maint-3.10/
        └── <hardware>/
            ├── <flow_graph>.grc
            └── <flow_graph>.py
```

Examples in the current plugins include category directories such as:

- `iq_record_flow_graphs`
- `iq_playback_flow_graphs`
- `iq_inspection_flow_graphs`
- `conditioner_flow_graphs`
- `detection_flow_graphs`
- `fuzzing_flow_graphs`

Some categories have additional purpose-specific nesting, and some non-hardware-specific flow graphs may omit the hardware directory. Follow the nearest existing canonical example for that workflow.

Use the established GNU Radio maintenance directory names exactly:

- `maint-3.8`
- `maint-3.10`

For hardware-specific leaves, use the existing short hardware directory names already used by FISSURE, such as `b2x0`, `hackrf`, `rtl2832u`, `plutosdr`, `limesdr`, and the corresponding names used by nearby canonical flow graphs. The user-facing FISSURE hardware name and the filesystem directory name are not necessarily the same; keep that mapping in the Operation.

Keep the `.grc` source and its generated `.py` file together in the appropriate leaf directory when the flow graph is intended to be compiled and run from the plugin. This allows installation/compilation tooling to find the expected GRC files and keeps the generated runtime file next to its source.

Before adding a new flow-graph category directory, inspect the installer/compilation logic and existing plugin categories. If the installer recognizes specific folder names, either use the appropriate recognized category or make an intentional framework/installer change rather than creating a directory that installation will silently ignore.

### Runtime Resolution

Resolve the active GNU Radio maintenance version with the normal FISSURE library-version mechanism instead of hardcoding one version globally.

Hardware-to-flow-graph resolution belongs in the Operation, not in `actions.py`.

The Operation should select:

1. the active `maint-*` version;
2. the configured FISSURE hardware type;
3. the established hardware directory and flow-graph implementation;
4. the generated Python file appropriate for that combination.

Fail clearly when the selected maintenance-version/hardware combination is not actually present. Do not advertise support based only on a placeholder directory.

When launching generated flow graphs or subprocesses:

- use plugin-relative paths;
- use the correct working directory;
- use the Operation's subprocess environment helpers when graphical/Xpra context applies;
- drain or otherwise handle subprocess output when necessary;
- terminate cleanly on Stop;
- escalate to kill only when graceful termination fails.

## Offline and Data-Analysis Operations

For file-oriented or analysis-heavy Operations, validate more than algorithmic correctness on tiny fixtures.

- Exercise representative input sizes when practical.
- Avoid rereading or re-decoding the same large file multiple times when intermediate results can be reused.
- Prefer memory mapping, streaming, chunking, or bounded working sets when the format permits it.
- Reuse expensive intermediate analysis such as pulse detection rather than recomputing it independently for reports and plots.
- Keep detailed supporting measurements in Artifacts when appropriate, while returning a concise operator-visible Inspection result.
- Preserve `unknown`, `unsupported`, and `not observable` as distinct states from `false`, `zero`, or `not detected`.
- Do not tune an algorithm solely until synthetic validation fixtures match; distinguish a general analysis improvement from overfitting the test corpus.

Performance validation should reflect the expected operational scale. A test that passes on a small synthetic file does not establish acceptable behavior on a large capture.

## Long-Running Operations and Stop Behavior

Long-running Operations must remain responsive to Stop.

Use the Operation framework's `_stop` flag and cooperative async behavior. Prefer `_sleep_stop_aware(...)` where it fits rather than one long uninterruptible sleep.

Loops should periodically yield to the event loop.

Clean up subprocesses, GNU Radio top blocks, temporary handles, monitor modes, or similar resources in reliable cleanup paths, normally `finally` and/or the Operation teardown mechanism.

A Stop request targets the specific active Operation ID. Do not implement plugin Stop behavior by stopping every Operation on the Sensor Node or every Operation in the plugin.

The Sensor Node runner owns Operation registration, finalization, teardown sequencing, and removal from the active-operation registry.

Use `status_callback` for useful Operation progress, but do not create a parallel started/stopped lifecycle protocol. Be careful about forcing a global-looking `Idle` status from one Operation when other Operations may still be active; the Sensor Node runner owns the overall idle transition after the last active Operation completes.

## Local and Remote Execution

Assume an Action may execute on a remote Sensor Node unless its tags explicitly restrict it.

Do not write plugin logic that only works because the Dashboard and Sensor Node happen to share:

- a process;
- a working directory;
- a filesystem;
- local hardware;
- local GUI state.

Execution, lifecycle, status, detections, results, and artifacts should travel through the normal Sensor Node -> HIPRFISR -> Dashboard paths.

Remote graphical presentation such as Xpra is presentation only. It should not create a second execution or messaging architecture.

## Reusing Existing Actions

If a plugin or mission package wants to expose an Action that already belongs to another plugin, delegate it instead of copying it.

Use the existing delegated-action mechanism so the destination inherits the source Action's:

- coroutine behavior;
- schema;
- tags;
- hardware compatibility.

`Mission-01` demonstrates this pattern.

When a plugin truly depends on another plugin being present, use the existing plugin dependency mechanism rather than silently copying its implementation.

## `plugin.yaml`

Keep the manifest small and accurate.

Normal fields include:

- `name`
- `version`
- `description`

Keep the manifest name aligned with the plugin directory.

Increment the plugin version when the packaged plugin changes in a way that remote nodes need to recognize as an update.

Use `required_plugins` when there is a real plugin dependency.

Cleanup is opt-in. Do not add:

```yaml
cleanup: true
```

unless safe cleanup behavior has been explicitly designed and reviewed.

## `setup.py`: Safe by Default

New plugins should include the normal `setup.py` shell when expected by the plugin lifecycle, but it should be a no-op by default.

Do not automatically add package installation, driver installation, udev changes, system configuration, service manipulation, permissions changes, global Python installs, cleanup, repair behavior, or other host modifications simply because the plugin may eventually need them.

Let the plugin author/user explicitly define and review external setup requirements.

The default shell should preserve the standard actions:

```text
check
install
cleanup
```

while reporting that no external setup is currently required.

If setup behavior is later added:

- keep it plugin-owned;
- make it idempotent;
- make `check` accurately detect readiness;
- install only what the plugin actually requires;
- avoid modifying unrelated host state;
- never remove shared dependencies during cleanup;
- opt into cleanup in `plugin.yaml` only when removal is safe.

The fact that an Operation calls an external command does not by itself justify automatically installing that command on a user's system.

### External Tool Assumptions and Validation

When a plugin depends on third-party software, first determine what FISSURE already knows about that tool before inventing setup or assuming a command-line interface.

When the development environment is available:

- identify the current operating system/version when it affects support;
- inspect the relevant FISSURE installer scripts, modes, verification commands, and existing integrations for the tool;
- use those repository patterns to understand whether the command/version is expected to be supported in that environment;
- if the executable is already present, non-destructive checks such as `command -v`, `--version`, `--help`, or an existing FISSURE verification command may be used to confirm assumptions about the installed tool.

Do not install packages, change system configuration, or otherwise modify the host merely to validate a plugin unless the user explicitly requested that work.

Mocks, fixtures, and fake subprocesses are still useful for validating FISSURE integration, parsing, lifecycle, and error handling. They should not be treated as proof that an unavailable real executable accepts the same arguments or produces the same output. If the real tool cannot be checked, validate what is practical and leave that external-tool behavior for real-system testing.

## Prefer Plugin Changes Before UI/Core Changes

When implementing a new capability, first determine whether it can be expressed through:

- Action schema;
- Action tags;
- hardware metadata;
- an Operation;
- existing callbacks;
- plugin-owned scripts/resources/flow graphs.

Do not add Dashboard-specific code or core callbacks merely to make one plugin work when the existing generic plugin path is sufficient.

Core changes are appropriate when they add a reusable framework capability rather than one plugin's special case.

## Canonical Examples

Choose examples based on the behavior being implemented rather than copying the newest plugin wholesale.

Useful places to inspect include:

- `Plugins/Base/` - broad built-in RF, IQ, analysis, geolocation, media, and detector patterns;
- `Plugins/WiFi/` - plugin-owned helper libraries/resources, hardware-specific Actions, detections, and geolocation workflows;
- `Plugins/Dummy/` - examples of FISSURE data types and callback paths;
- `Plugins/X10/` - hardware-aware Action exposure and Operation-owned flow-graph selection;
- `Plugins/Mission-01/` - delegated Actions instead of duplicated implementations;
- `fissure/utils/plugins/operations.py` - Operation base class and supported framework services;
- `fissure/Sensor_Node/SensorNode.py` - authoritative Operation runner/lifecycle behavior;
- `fissure/utils/plugin.py` - Action discovery, schema loading, tags, hardware filtering, delegation, manifests, and setup lifecycle.

Do not treat a newly generated or not-yet-reviewed plugin as a canonical example.

## Validation Checklist

Before considering a new or modified plugin complete, check the actual path through FISSURE. Unit tests and direct Operation tests are not sufficient evidence of integration when the capability is normally launched through a Dashboard workflow. Exercise at least one representative end-to-end run through the intended UI path when practical.

### Action exposure

- The intended async Action is discovered.
- No helper function is accidentally exposed as an Action.
- No development/test-only capability was exposed as an Action unless it is also an intended user workflow.
- The schema name exactly matches the Action.
- Schema parameters reach the intended Operation inputs.
- User-facing parameters represent meaningful choices rather than incidental implementation tuning.
- Tags place the Action in the intended workflows.
- Inspection Actions use the active Inspection context rather than exposing redundant file/context parameters.
- Framework-provided Operation IDs are preserved when the workflow uses them for correlation.
- `client.*` and `node.*` tags do not create unintended restrictions.
- `ACTION_HARDWARE` uses exact FISSURE hardware names.
- The Action appears for supported configured hardware and is hidden only where intended.

### Operation execution

- The Operation file is under `operations/`.
- The entry class is `OperationMain`.
- The constructor accepts the parameters and standard framework callbacks/services it actually needs.
- The Action launches through `run_plugin_operation(...)`.
- Local and remote Sensor Node assumptions are correct.
- Long-running loops respond to Stop.
- Stop targets the correct Operation ID.
- Subprocesses/flow graphs/resources are cleaned up reliably.
- The Operation does not manipulate the Sensor Node's operation registry directly.

### Results and framework integration

- Existing callbacks are used for standard FISSURE data types.
- Callback payloads follow current canonical shapes.
- Node position comes through `position_callback` when needed.
- Accuracy, uncertainty, confidence, and similar values are sourced or legitimately derived rather than invented.
- Artifacts use the existing Artifact framework.
- Artifact files are written into managed Operation storage before registration.
- Generated results reach HIPRFISR/Dashboard through normal framework paths.
- Inspection results complete the actual Dashboard workflow: Start -> Operation -> Inspection callback -> Completed -> View Result / Save as Finding, with the same correlated Operation ID.
- Analysis results preserve unsupported/not-observable states instead of coercing them to false values.
- Representative data sizes were checked for avoidable repeated I/O or recomputation when the Operation performs offline analysis.
- Map/TAK behavior uses existing target/detection/CoT mechanisms instead of a plugin-specific transport.

### Plugin packaging and host safety

- Support files live under the appropriate plugin supplemental directory.
- Paths are plugin-relative and do not depend on an accidental working directory.
- `plugin.yaml` is accurate and versioned appropriately.
- For third-party commands, relevant FISSURE installer/support information was checked and any practical non-destructive local verification was performed.
- `setup.py` is still a safe no-op unless external setup was explicitly requested.
- Cleanup remains disabled unless safe plugin-owned cleanup was deliberately implemented.
- The plugin does not silently alter the user's system during deployment or first execution.

## When in Doubt

Inspect the core path before inventing a plugin-specific mechanism.

The preferred sequence is:

```text
existing framework mechanism
    -> existing plugin pattern
        -> plugin-owned implementation
            -> reusable core enhancement only if necessary
```

Keep Actions simple, put execution behavior in Operations, keep supporting code with the plugin, and let FISSURE core own transport, lifecycle, and shared data types.
