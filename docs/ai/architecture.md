# FISSURE Architecture Guidance for AI Development

This document explains the architectural intent and system boundaries that are easy to misunderstand by reading individual FISSURE files in isolation.

Use this together with the repository-level `AGENTS.md` and any task-specific guidance under `docs/ai/`.

This is not intended to duplicate class-by-class code documentation. Inspect the current source for implementation details. Use this document to understand what each major component is responsible for, where state should live, how data normally moves through the system, and which boundaries should be preserved when adding new capabilities.

## Architectural Priorities

FISSURE is designed around several broad principles:

- The Dashboard is an operator interface, not the execution environment for remote RF work.
- HIPRFISR is the central coordination hub between clients, Sensor Nodes, specialized backend services, shared state, TAK, and other integrations.
- Sensor Nodes own hardware-facing execution and plugin Operations.
- Plugins should extend the framework rather than create parallel execution, messaging, lifecycle, or data-model systems.
- Structured results should move through existing FISSURE callbacks and shared data types.
- Local and remote Sensor Nodes should follow the same logical workflows whenever practical.
- TAK is an integration and presentation path, not the canonical source of FISSURE state.
- Large or binary files should use the Artifact system and dedicated transfer path rather than the JSON command/control channel.
- Current source code is authoritative for implemented behavior. Active plans may intentionally describe behavior that has not yet been fully implemented.

## Major Components

The main runtime architecture is:

```text
                         +----------------------+
                         |      Dashboard       |
                         |  Frontend + Backend  |
                         +----------+-----------+
                                    |
                               PAIR / ZMQ
                                    |
                                    v
+----------------+        +---------+----------+        +----------------+
| Protocol       |<------>|                    |<------>| Target Signal  |
| Discovery      | DEALER |      HIPRFISR      | DEALER | Identification|
| (specialized)  |/ROUTER |       Hub          |/ROUTER | (specialized) |
+----------------+        |                    |        +----------------+
                          |                    |
                          +---------+----------+
                                    |
                    ROUTER / DEALER command + heartbeat
                     TCP for remote / IPC for local nodes
                                    |
                     +--------------+--------------+
                     |              |              |
                     v              v              v
              +------------+ +------------+ +------------+
              | Sensor Node| | Sensor Node| | Sensor Node|
              |   local    | |   remote   | |   remote   |
              +------------+ +------------+ +------------+
                     |
                     +-- hardware
                     +-- plugins / Actions / Operations
                     +-- GPS / position cache
                     +-- local ArtifactManager

HIPRFISR also owns or coordinates:
    - canonical node registry/state
    - Targets
    - SOIs
    - Artifact tracking and transfer routing
    - TAK connectivity/publication
    - persisted Listening Posts
    - database/library cache distribution
    - optional headless operation

A dedicated binary Artifact transfer plane exists separately from normal
heartbeat and JSON command/message channels.
```

The exact socket topology and ports are implementation details. Inspect the current communications code before modifying transport behavior.

## Dashboard

The Dashboard is split conceptually into two layers.

### Dashboard Frontend

The Dashboard Frontend owns:

- Qt widgets and UI state;
- tab initialization;
- user interaction;
- maps, tables, plots, controls, and selection state;
- visual presentation of Targets, SOIs, Detections, Artifacts, node state, and analysis results.

Most UI behavior belongs in the Dashboard Frontend, Slots, UI components, or closely related controllers.

Do not make Sensor Node or plugin code directly manipulate Dashboard widgets.

### Dashboard Backend

The Dashboard Backend is the Dashboard's asynchronous control-plane interface to HIPRFISR.

It owns responsibilities such as:

- connecting to and disconnecting from HIPRFISR;
- sending user-requested commands;
- receiving HIPRFISR callbacks/results;
- heartbeat state;
- requesting library/database cache data;
- node/tasking requests;
- plugin inventory/deployment requests;
- artifact download coordination;
- bridging received data into Dashboard callbacks that update the Frontend.

Do not put hardware execution or plugin implementation logic in the Dashboard Backend simply because the user initiated the operation from the GUI.

A normal operator request flows out through the Backend and is executed elsewhere.

## HIPRFISR

HIPRFISR is the coordination hub.

It should be treated as the central routing and aggregation point between:

- Dashboard clients;
- Sensor Nodes;
- Protocol Discovery;
- Target Signal Identification;
- TAK;
- Listening Posts;
- Artifact transfer services;
- shared/canonical operational state.

HIPRFISR can run without a Dashboard. Do not assume that the Dashboard process is always present.

### HIPRFISR Responsibilities

Current responsibilities include:

- routing callback-based commands between components;
- tracking Sensor Node identity and connection state;
- normalizing and forwarding node state;
- maintaining canonical Target state;
- maintaining canonical SOI state;
- processing/forwarding structured Detections;
- tracking Artifact manifests;
- coordinating Artifact binary transfers;
- TAK connection and publication;
- persisted Listening Post definitions/runtime services;
- selected geolocation aggregation and target update behavior;
- database/library cache distribution;
- lifecycle and heartbeat supervision for connected components.

New framework-wide coordination behavior generally belongs here rather than in a Dashboard widget or one arbitrary plugin.

Do not turn HIPRFISR into a repository for plugin-specific implementation logic. Plugin-owned behavior should remain in the plugin unless it is truly a reusable framework service.

## Sensor Nodes

Sensor Nodes are the execution environment for hardware-facing and plugin-based capabilities.

A Sensor Node may be:

- local to the Dashboard/HIPRFISR system;
- remote over IP;
- connected through supported lower-bandwidth transports such as Meshtastic for applicable workflows.

For IP Sensor Nodes, the local and remote cases intentionally use the same logical Sensor Node architecture:

- remote nodes connect to HIPRFISR over TCP;
- local nodes use IPC;
- both use the same general command/callback model.

Do not build a feature that works only because a local Sensor Node shares a filesystem, process environment, or GUI machine with the Dashboard.

### Sensor Node Responsibilities

Sensor Nodes currently own or coordinate:

- configured RF and other hardware;
- plugin Action execution;
- plugin Operation lifecycle;
- runtime resource locking;
- local Operation status;
- Operation IDs;
- Operation stop/finalization behavior;
- hardware/flow-graph execution;
- local GPS/position acquisition and caching;
- local ArtifactManager storage;
- Autorun execution;
- returning structured results upstream.

The Sensor Node should be the first common framework point for results generated by an Operation.

For example, Operations should use injected callbacks such as:

- detection callback;
- status callback;
- target callback;
- SOI callback;
- recommendation callback;
- inspection callback;
- alert callback;
- TAK CoT callback when appropriate;
- position callback;
- ArtifactManager.

The Sensor Node then applies normal framework behavior and forwards results to HIPRFISR.

## Specialized Backend Components

FISSURE still contains specialized backend components such as:

- Protocol Discovery (`PD`);
- Target Signal Identification (`TSI`).

These connect to HIPRFISR through the backend ROUTER/DEALER path and maintain their own heartbeat/message loops.

They are valid parts of the current architecture, but they should not automatically be treated as the extension point for every new signal-analysis capability.

Modern FISSURE development increasingly uses:

- plugins;
- Actions;
- Operations;
- shared framework callbacks;
- Dashboard Signal Analysis workflows.

Before adding logic to PD or TSI, confirm that the capability truly belongs in that specialized service rather than in a plugin Operation or reusable framework service.

Do not refactor legacy components merely because newer plugin-based patterns exist unless the task specifically calls for that migration.

## Communications Model

Normal FISSURE control-plane messaging is callback-oriented.

A command message contains a `MessageName`. The receiving component resolves that name against its registered callback table and invokes the corresponding async callback with the supplied parameters.

Conceptually:

```text
sender
  -> MessageName + Parameters
  -> FISSURE communications layer
  -> receiving component callback registry
  -> matching callback
  -> framework/state/UI action
```

This pattern is used throughout Dashboard, HIPRFISR, Sensor Node, PD, and TSI communications.

### Preserve Existing Message Paths

When adding a feature:

1. Find the closest existing data or command path.
2. Reuse its callback/message pattern.
3. Add a generic framework callback only if the existing framework genuinely lacks the required data type.
4. Avoid plugin-specific point-to-point message systems.

Do not directly bypass HIPRFISR for ordinary distributed framework communication just to save a callback.

### Heartbeats Are Separate

Heartbeat traffic is separated from normal message traffic.

Heartbeat state is used for:

- connection monitoring;
- node health;
- node status;
- position/state propagation;
- connection gating;
- Dashboard node-state updates.

Do not use heartbeats as a general high-volume data transport.

### ROUTER Identities Are Transport State

HIPRFISR tracks stable Sensor Node UUIDs separately from ZMQ ROUTER identities.

Treat the Sensor Node UUID as the logical identity.

ROUTER/DEALER socket identities are transport/session details and may change. Do not persist or expose them as the canonical node identity.

## Typical Plugin Execution Path

A normal plugin-triggered workflow should conceptually look like:

```text
User / Dashboard
    |
    v
Dashboard Backend
    |
    v
HIPRFISR
    |
    v
Sensor Node
    |
    v
Plugin Action
    |
    v
Operation
    |
    +--> hardware / GNU Radio / helper script
    |
    +--> standard FISSURE callback
             |
             v
        Sensor Node
             |
             v
          HIPRFISR
             |
             +--> canonical state processing
             +--> Dashboard
             +--> TAK when appropriate
             +--> Artifact tracking/transfer when appropriate
```

The exact callbacks differ by result type.

Do not collapse these layers into a direct Dashboard-to-plugin implementation for convenience.

## Actions and Operations

Actions and Operations are related but different architectural concepts.

### Action

An Action is the user-facing capability exposed by a plugin.

It defines or contributes:

- Action name;
- schema;
- tags;
- hardware compatibility;
- delegation;
- call into an Operation.

Actions should remain thin. Detailed plugin rules live in `docs/ai/plugins.md`.

### Operation

An Operation is an execution instance on a Sensor Node.

Each Operation has its own lifecycle and Operation ID.

The Sensor Node Operation runner owns:

- import/instantiation;
- standard callback injection;
- execution context injection;
- setup;
- runtime resource allocation;
- registration;
- task execution;
- stop requests;
- teardown;
- registry removal;
- node busy/idle transitions.

Do not reproduce these mechanisms inside the Operation.

### Execution Context

Operations currently receive an in-memory `execution_context`.

The Sensor Node runner extracts `_fissure_execution_context` from Action parameters and assigns it separately to the Operation instance.

Use execution context for framework/provenance context rather than mixing parent Action metadata into the Operation's ordinary user parameters.

Do not assume execution-context behavior is finished architecture. Review relevant active plans before changing provenance behavior.

## Core Operational Information Model

Several related data types appear across Tactical, Signal Analysis, plugins, and distributed execution. They do not all have identical ownership or persistence semantics.

### Sensor Node State

Sensor Node state describes the current node itself.

Examples include:

- UUID;
- nickname/callsign;
- network information;
- connection state;
- current status;
- version;
- GPS source and validity;
- latitude/longitude/altitude;
- Autorun state.

The Sensor Node reports state/heartbeat information.

HIPRFISR normalizes and stores the current node registry record, then forwards public node state to the Dashboard.

HIPRFISR may also project node state into TAK as a node track.

The Dashboard should consume the normalized node state rather than independently inventing a second truth for connection state.

### Detection

A Detection is a transient observation.

Current native Detection behavior intentionally treats Detections as transient rather than as long-lived authoritative objects.

A Detection may contain:

- detector/source;
- node UID;
- Operation ID;
- detection ID;
- timestamp/observation time;
- frequency/signal measurements;
- classification or detector metadata;
- location.

The Sensor Node is the first common routing point for native Detections.

The Sensor Node may:

- add framework identity fields;
- add Operation context;
- use node position as a fallback when appropriate;
- feed local Autorun/detector behavior;
- send the Detection upstream.

HIPRFISR may:

- normalize/enrich it;
- feed geolocation logic;
- forward it to the Dashboard;
- project it into TAK when a valid location is available.

Do not turn every Detection into a Target automatically. Promotion and Target creation are separate workflow decisions unless a specific workflow explicitly defines otherwise.

### SOI

An SOI is an investigation-centered signal record.

HIPRFISR currently maintains canonical cumulative SOI records.

SOIs are append-oriented:

- Artifact links accumulate;
- Detection snapshots can accumulate;
- analysis history accumulates;
- partial updates should not erase previously known values.

An SOI may carry signal identity/classification, frequency, analysis stage, location, Artifacts, Detection relationships, and analysis history.

The Dashboard presents SOIs across Tactical and Signal Analysis workflows, but should not become the canonical distributed store.

When extending SOI behavior, preserve cumulative merge semantics unless the task explicitly changes the data model.

### Target

A Target is a longer-lived operational entity.

HIPRFISR currently owns canonical Target records.

Targets may accumulate:

- identity;
- classification;
- RF information;
- protocol-specific information;
- location;
- geolocation state;
- history;
- Artifacts;
- source SOI relationships;
- recommendations;
- other operational metadata.

Target updates are generally cumulative. `targetPatch` exists to patch authoritative Target state rather than forcing every caller to rewrite the complete record.

Target history and Target-owned Artifact relationships should remain distinct from SOI evidence when the current model distinguishes them.

Do not make the Dashboard's local Target table the authoritative store.

### Artifact

An Artifact represents managed output produced by an Operation or workflow.

Artifact metadata is distinct from Artifact file bytes.

A Sensor Node Operation normally creates/registers Artifacts through its local ArtifactManager.

The Sensor Node then notifies HIPRFISR of the Artifact manifest.

HIPRFISR maintains Artifact tracking metadata and can coordinate retrieval.

Large Artifact file payloads use a dedicated binary transfer plane rather than normal JSON command sockets.

The Dashboard maintains its own verified local Artifact download cache when files are requested.

Important architectural rule:

```text
Artifact metadata/control -> normal framework callbacks/messages
Artifact file bytes       -> dedicated Artifact transfer plane
```

Do not put large file contents or IQ data into ordinary command callback payloads.

### Inspection

Inspection results are structured analysis output returned through the Inspection callback path.

They are distinct from a user-edited Finding.

The Dashboard currently has Inspection workflows that can turn measurements or plugin results into editable Findings.

### Finding

Finding is currently more of a Signal Analysis/Dashboard workflow concept than a universal distributed transport type.

Inspection Findings can be created and edited in the Dashboard and can be saved into SOI analysis history.

Do not assume a new generic `finding_callback` or hub-level Finding store exists merely because Findings appear in the information model/UI.

If a task requires Findings to become a first-class distributed framework entity, treat that as an explicit architecture change.

### Alert

Alerts are event/notification-oriented information.

Use the existing alert path rather than inventing a plugin-specific notification channel.

Alerts may be surfaced through Dashboard and TAK behavior depending on their form.

Do not use Alerts as a substitute for persistent Target or SOI state.

### Action Recommendation

Recommendations are structured follow-on Action suggestions, currently associated with Targets.

They should use the existing recommendation callback/Target update mechanism.

Do not create a second independent recommendation store in a plugin.

## Position and Location Semantics

FISSURE distinguishes between:

- Sensor Node position;
- observed object/signal location;
- Target location.

A Sensor Node owns acquisition/caching of its own position.

Operations that need node position should request it through the existing position callback rather than opening their own gpsd or other GPS connection.

A Detection may use Sensor Node position as an observation-location fallback when appropriate.

However, if the detected object has its own real position, preserve that object position.

For example, an aircraft-reported ADS-B latitude/longitude is not the Sensor Node location and should not be overwritten by GPS fallback.

Location validity should be explicit when a workflow intentionally has no meaningful location.

## TAK

TAK is an external situational-awareness integration.

HIPRFISR owns the primary TAK client and publication behavior.

Current FISSURE data such as:

- Sensor Nodes;
- Detections;
- Targets;
- Alerts;
- tracks;
- other supported events

may be projected into Cursor on Target messages.

### TAK Is Not the Internal Source of Truth

Do not design a feature so that FISSURE must parse its own outgoing TAK message to recover internal state.

Maintain internal structured FISSURE records first, then derive TAK output.

Similarly, Dashboard mapping should work from internal FISSURE state without requiring a TAK Server.

### Prefer Native Data Types Before Raw CoT

If information naturally represents a FISSURE:

- Detection;
- Target;
- Alert;
- SOI;
- status update;

use that native callback/path first.

Use custom/raw `tak_cot_callback` behavior when the native framework types are not the correct representation.

This preserves a useful internal data model even when TAK is disabled.

## Artifact Transfer Plane

Artifact file transfer is intentionally isolated from normal FISSURE ZMQ command and heartbeat channels.

The current transfer system includes:

- a dedicated HIPRFISR Artifact transfer ROUTER;
- registered Dashboard and Sensor Node binary peers;
- transfer IDs;
- chunked binary frames;
- per-file size/checksum validation;
- atomic file finalization;
- multi-file Artifact support;
- separate Dashboard and HIPRFISR caches.

The Artifact transfer router routes binary frames but does not replace Artifact metadata tracking.

Do not extend the normal callback channel with binary payload hacks.

If a new feature needs large-file movement, first determine whether it should use or extend the Artifact transfer plane.

## Library and Database Data

HIPRFISR hosts the database-backed library/cache path used by the Dashboard and specialized components.

The Dashboard requests a cached representation of the library through HIPRFISR rather than treating the UI as the database owner.

When modifying shared library behavior:

- use the existing library utilities;
- preserve cache refresh behavior;
- consider Dashboard and Protocol Discovery consumers;
- avoid having one plugin or widget open a parallel database access path unless there is a strong architectural reason.

## Listening Posts

Listening Posts are hub-level external-input integrations.

HIPRFISR currently owns:

- persisted Listening Post definitions;
- runtime Listening Post services;
- autostart behavior.

Listening Posts are conceptually different from Sensor Node plugin Operations.

A Listening Post consumes external information into the FISSURE ecosystem from sources such as supported message/network/file interfaces.

Do not force every external information source into a Sensor Node plugin if it is actually a hub-side Listening Post use case.

Likewise, do not move hardware-facing RF execution into Listening Posts.

## Local vs Remote Assumptions

Treat remote execution as a first-class design constraint.

Code should not assume that Dashboard, HIPRFISR, and Sensor Node share:

- filesystem paths;
- environment variables;
- hardware devices;
- processes;
- display servers;
- Python imports outside deployed plugin contents;
- user home directories.

Local Sensor Node support exists for convenience, but it should not become the hidden architectural requirement.

### Files

If a result must move between systems:

- use an Artifact when it represents managed output;
- use the existing file-transfer path when that workflow specifically calls for normal Sensor Node file movement;
- do not assume the Dashboard can open a Sensor Node-local path.

### Graphical Tools

Remote GUI presentation such as Xpra is presentation infrastructure.

The underlying Action/Operation still runs on the Sensor Node.

Do not implement remote graphical tools by moving execution back into the Dashboard.

## Lifecycle and Status Ownership

Ownership matters.

### Sensor Node Operation Lifecycle

The Sensor Node runner is the owner of plugin Operation lifecycle.

It controls:

- operation registration;
- active-operation tracking;
- start task;
- stop request;
- teardown;
- registry removal;
- node busy/idle edge transitions.

An Operation should not directly manipulate the Sensor Node operation registry.

An Operation should not assume it is the only active Operation on the node.

### Node Status

`current_status` is Sensor Node state.

Operation status publication is intentionally rate-limited/edge-oriented to avoid flooding the control plane.

The overall node should return to Idle only when the framework determines that the last active Operation is finished.

Do not have one plugin Operation globally force the Sensor Node to Idle while other Operations may still be running.

### Connection State

HIPRFISR derives distributed node connection/state information from heartbeats and the node registry.

The Dashboard receives normalized state updates.

UI controls should react to that framework state rather than maintaining unrelated connection truth.

## State Ownership Summary

Use this as a quick mental model:

```text
Dashboard
    owns:
        UI state
        user selections
        presentation caches
        local downloaded Artifact cache

HIPRFISR
    owns/co-ordinates:
        distributed routing
        normalized Sensor Node registry
        canonical Targets
        canonical SOIs
        hub Artifact tracking
        TAK integration
        Listening Posts
        shared geolocation aggregation
        database/library cache distribution

Sensor Node
    owns:
        hardware-facing execution
        plugin Operation lifecycle
        local resource locks
        GPS/position cache
        local Artifact creation/storage
        Autorun
        node runtime status

Plugin Action
    owns:
        capability exposure/schema/tags/hardware declaration
        thin dispatch to Operation

Plugin Operation
    owns:
        one execution instance
        capability-specific runtime logic
        hardware/tool interaction
        plugin-specific generated results

PD / TSI
    own:
        their specialized processing responsibilities

TAK
    receives:
        projections of FISSURE operational state/events
    does not own:
        canonical FISSURE state
```

## Common Architectural Mistakes

Avoid these patterns unless the task explicitly requires an architecture change.

### Putting implementation logic in the Dashboard

Bad pattern:

```text
button click -> Dashboard directly runs RF tool
```

Preferred:

```text
button click -> Backend -> HIPRFISR -> Sensor Node -> Operation
```

### Creating plugin-specific transport

Bad pattern:

```text
plugin invents custom socket/callback for normal Detection/Target/status data
```

Preferred:

```text
plugin Operation -> existing standard callback -> normal framework path
```

### Treating local execution as the architecture

Bad pattern:

```text
Dashboard reads /tmp/output.dat written by Sensor Node
```

Preferred:

```text
Sensor Node creates Artifact -> framework transfer -> Dashboard cache
```

### Treating TAK as internal state storage

Bad pattern:

```text
create CoT -> parse CoT back into Dashboard state
```

Preferred:

```text
update native FISSURE state -> derive Dashboard view and TAK projection
```

### Storing persistent distributed state only in the UI

Bad pattern:

```text
Target exists only in a Dashboard dictionary
```

Preferred:

```text
HIPRFISR owns canonical Target -> Dashboard receives/update view
```

### Bypassing framework lifecycle

Bad pattern:

```text
Operation manually inserts itself into Sensor Node registries
Operation manually declares global node Idle
```

Preferred:

```text
Sensor Node runner owns lifecycle; Operation implements setup/run/stop/teardown
```

### Duplicating GPS acquisition

Bad pattern:

```text
every plugin starts its own gpsd client
```

Preferred:

```text
Sensor Node owns position acquisition -> Operation uses position callback
```

### Sending large files over command callbacks

Bad pattern:

```text
JSON message contains base64 IQ file
```

Preferred:

```text
Artifact metadata through control plane
Artifact bytes through binary transfer plane
```

## Choosing Where New Code Belongs

Use this decision sequence.

### Is it UI/presentation behavior?

Put it in:

- Dashboard Slots;
- Frontend;
- UI components;
- a focused Dashboard controller.

### Is it a new hardware-facing or user-invoked capability?

Prefer:

- plugin Action;
- plugin Operation;
- plugin supplemental scripts/resources/flow graphs.

### Is it reusable execution behavior needed by many Operations?

Consider:

- Operation base class;
- Sensor Node framework service;
- focused utility module.

Do not move it to core until the reuse case is real.

### Is it canonical distributed coordination/state behavior?

Consider:

- HIPRFISR;
- HIPRFISR callback;
- shared state/model utility.

### Is it external data ingestion at the hub?

Consider:

- Listening Post architecture.

### Is it large managed output?

Use:

- Artifact architecture.

### Is it merely an external representation?

Keep native FISSURE state first, then add:

- TAK;
- export;
- file/report rendering;
- other presentation/integration.

## Working with Legacy and Transitional Code

FISSURE contains both older architecture and newer plugin/data-model patterns.

Do not assume either of these extremes:

- "old code exists, therefore every new feature should copy it";
- "new pattern exists, therefore all older code should be refactored immediately."

Instead:

1. Identify the current intended extension point.
2. Read relevant `docs/ai/` guidance.
3. Check `docs/plans/` for active migrations.
4. Inspect several current implementations.
5. Make the smallest change that fits the intended architecture.
6. Avoid unrelated migration work unless requested.

Examples of transition areas may include:

- older built-in flow-graph execution versus plugin Operations;
- specialized PD/TSI services versus newer Signal Analysis/plugin workflows;
- evolving provenance/execution context;
- legacy record shapes that are still accepted for compatibility.

Compatibility code may be intentional. Do not remove it solely because a cleaner newer shape exists.

## Validation Across Boundaries

A change is not architecturally validated merely because one function works.

For distributed features, check the applicable chain:

```text
UI request
-> Dashboard Backend
-> HIPRFISR routing
-> Sensor Node
-> Action
-> Operation
-> standard result callback
-> Sensor Node framework
-> HIPRFISR processing/state
-> Dashboard callback/UI
-> TAK/Artifact side effects when applicable
```

Not every task exercises every layer, but determine which layers the feature actually crosses.

When hardware is required, distinguish:

- code-path review;
- simulated/offline validation;
- real hardware validation.

Do not claim hardware validation when only the first two were performed.

## Canonical Files to Inspect

When architecture questions arise, useful current sources include:

```text
fissure/Dashboard/Frontend.py
fissure/Dashboard/Backend.py
fissure/callbacks/DashboardCallbacks.py

fissure/Server/HiprFisr.py
fissure/callbacks/HiprFisrCallbacks.py

fissure/Sensor_Node/SensorNode.py
fissure/callbacks/SensorNodeCallbacks.py

fissure/comms/FissureZMQNode.py
fissure/comms/ArtifactTransfer.py

fissure/utils/artifacts.py
fissure/utils/plugin.py
fissure/utils/cot_utils.py
fissure/utils/tak_messages.py

fissure/Server/ProtocolDiscovery.py
fissure/Server/TargetSignalIdentification.py

fissure/ListeningPosts/

Plugins/
```

For plugin-specific architectural rules, read:

```text
docs/ai/plugins.md
```

## Final Rule

When deciding how to implement something in FISSURE, preserve the framework boundaries before optimizing for the shortest local code path.

The preferred direction is:

```text
native FISSURE data model
    -> existing framework callback
        -> owning runtime component
            -> canonical hub processing/state
                -> UI / TAK / Artifact / integration projection
```

New code should make FISSURE more internally consistent, not create a special-case path that only one feature understands.
