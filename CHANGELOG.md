# Change Log
All notable changes to this project will be documented in this file.

## 2026-7-22

Add dedicated remote artifact transfer and richer TAK artifact metadata

### Added

- Added a dedicated binary artifact-transfer path for remote Sensor Node artifacts.
- Added HIPRFISR-side artifact transfer handling with temporary file writes, size validation, SHA-256 verification, and atomic finalization.
- Added reusable artifact streaming from Sensor Nodes for Dashboard and TAK retrieval workflows.
- Added expanded artifact metadata delivery for TAK clients, including type, size, timestamps, checksum, logical source URI, and structured metadata.
- Added selected-artifact details support in WinTAK using the enriched FISSURE artifact metadata.

### Changed

- Updated Dashboard remote artifact downloads to use the dedicated transfer channel instead of the normal command-message path.
- Updated TAK artifact retrieval so HIPRFISR first receives and verifies remote artifacts through the binary transfer channel before creating the existing TAK data package.
- Updated artifact transfer routing so HIPRFISR can act as a local transfer destination in addition to the Dashboard.
- Updated remote artifact retrieval to keep command traffic limited to transfer coordination and metadata rather than file payloads.
- Preserved the existing TAK data-package delivery mechanism while replacing the internal Sensor Node-to-HIPRFISR artifact transport.

## 2026-7-21

Streamline Tactical target and ecosystem review workflows

### Added

- Added scrollable compact and full-detail views for Tactical Targets.
- Added right-click Target actions for plotting, zooming, map removal, row deletion, and clearing.
- Added right-click Node Roster actions for map navigation and row management.
- Added right-click Alert actions for plotting, zooming, map removal, row deletion, and clearing.
- Added theme-aware styling for dynamically generated Tactical multi-node action parameters.

### Changed

- Reworked the Tactical Targets layout to prioritize the target list, dynamic details, geolocation controls, and plugin actions.
- Moved secondary Target plotting and row-management controls out of the permanent layout and into the Target context menu.
- Updated Target deletion and clearing to remove corresponding map overlays.
- Simplified the Tactical Ecosystem Node Roster to keep only Select All, Unselect, and Refresh Status visible.
- Removed permanent Alert action buttons and expanded the Alerts table into the available space.
- Updated Tactical multi-node parameter panels and generated labels to follow light, dark, and custom themes.

## 2026-7-21

Streamline Tactical SOI and Node Target review workflows

### Added

- Added scrollable dynamic SOI details with compact and full-detail views.
- Added right-click SOI actions for refreshing, deleting, clearing, plotting, zooming, and removing map items.
- Added right-click Node Target actions for details, filtering, plotting, zooming, map removal, and row management.
- Added target ID shortening with full-value tooltips in the Tactical Node Targets details panel.

### Changed

- Reworked the Tactical SOI layout to prioritize evidence review and promotion actions.
- Moved secondary SOI controls from permanent buttons into the results-table context menu.
- Updated Tactical SOI details to show a concise operational summary by default while preserving access to all structured fields.
- Reworked the Tactical Node Targets layout around permanent Refresh Targets and Query Actions controls.
- Moved secondary Node Target controls from permanent buttons into the results-table context menu.
- Kept Node Target refresh behavior manual so displayed distances remain explicit snapshots relative to the selected Sensor Node.

## 2026-7-20

Unify detection promotion, simulation, and review styling across Dashboard and WinTAK

### Added

- Added authoritative detection-to-SOI and detection-to-Target promotion paths shared by Tactical, TSI Detector, and WinTAK.
- Added complete structured detection forwarding during promotion so detector-specific fields are preserved.
- Added Simulation as a TSI Detector mode.
- Added Dummy detector discovery in the TSI Detector workflow through RF Simulation tags.
- Added reusable themed details-panel and parameter-panel styles for Tactical and TSI interfaces.
- Added theme-aware styling for dynamically generated Tactical action parameter labels.

### Changed

- Replaced Tactical and TSI detection promotion behavior with direct HIPRFISR record promotion instead of plugin-action execution.
- Updated promoted SOIs and Targets to use generic detection-promotion source metadata.
- Updated promoted detection normalization to support Tactical, TSI, and WinTAK field aliases consistently.
- Updated promoted SOI location handling to use detection coordinates, Sensor Node coordinates, or a valid fallback TAK point.
- Updated Tactical action parameter and selected-detection panels to use neutral structural borders.
- Kept the TSI selected-detection panel border aligned with the TSI blue accent styling.
- Updated light, dark, and custom themes so detection details and dynamic parameter panels follow the active color palette.
- Updated disabled panel states to use recessed backgrounds and disabled text colors.
- Updated the Dummy detector description to identify it as a simulated RF detector for workflow testing.

## 2026-7-19

Improve Tactical and TSI detection review workflows

### Added

- Added scrollable dynamic detection details panels for Tactical and TSI detector results.
- Added Promote to Target actions for detections in both Tactical and TSI workflows.
- Added right-click result-table actions for clearing, plotting, zooming, removing, and deleting detections.
- Added a persistent TSI detector blacklist management dialog.
- Added automatic first-row selection and selected-detection detail updates for TSI detector results.

### Changed

- Reworked Tactical and TSI detection layouts to prioritize result review and promotion workflows.
- Moved secondary Tactical detection actions from permanent buttons into a context menu.
- Moved TSI blacklist controls out of the main detector layout and into a popup dialog.
- Updated detection details rendering to display all non-empty structured fields, including nested values.
- Excluded raw XML and raw transport payloads from the primary detection details view.
- Rebalanced TSI detector plot, results, and selected-detection panel sizing.

## 2026-7-17

Separate TSI Detector and Conditioner functionality from legacy slot handling

### Changed

- Moved TSI Detector functionality into a dedicated `detector.py` module.
- Moved TSI Conditioner functionality into a dedicated `conditioner.py` module.
- Updated the TSI slot package to expose the Detector, Conditioner, and Feature Extractor modules alongside the remaining legacy handlers.
- Consolidated shared utility functions to prevent duplicate definitions across wildcard-imported TSI modules.
- Reduced the remaining legacy TSI slot code to the Classifier, SOI Aggregator, and Direction Finding workflows.
- Kept Dashboard-level plot construction where required while moving tab-specific control initialization into the corresponding TSI modules.

## 2026-7-16

Rework TSI Feature Extractor workflow around plugin actions, managed artifacts, and SOI analysis

### Added

- Added a consolidated TSI Feature Extractor workflow for Files, Folder, Artifact, and SOI inputs.
- Added time-domain, frequency-domain, combined, all-available, and custom feature extraction profiles.
- Added schema-driven plugin-action querying, parameter customization, execution, and stop controls.
- Added multi-file selection for Files input and filtered batch processing for Folder input.
- Added IQ preview support for local and managed inputs.
- Added local and remote Feature Extractor execution through selected Sensor Nodes.
- Added Local Results, New Analysis Artifact, Attach to Existing SOI, and Create New SOI from Input destinations.
- Added feature results display, CSV and JSON export, feature plotting, and result-file access.
- Added managed source-IQ and feature-analysis artifact relationships for SOI workflows.
- Added SOI refresh controls for the Dashboard Feature Extractor and WinTAK.
- Added authoritative SOI list retrieval so each client can refresh its own SOI view independently.
- Added dedicated Feature Extractor slot handling within the reorganized TSI slot package.

### Changed

- Replaced the previous Feature Extractor interface with a selected-node, plugin-driven workbench.
- Updated feature extraction operations to support explicit file lists, filtered folder batches, managed Artifact and SOI inputs, and operation-scoped outputs.
- Updated Feature Extractor results and reports to preserve source, operation, profile, and artifact metadata.
- Updated local input behavior so Files supports explicit multi-selection while Folder processes every filtered file.
- Updated TSI slot organization by moving legacy handlers into a package and separating Feature Extractor functionality.
- Updated Dashboard styling, navigation, ribbon state, selected-node gating, and local-versus-remote availability rules.
- Updated SOI and Artifact callbacks to support authoritative refreshes and durable analysis relationships.

## 2026-7-09

Rework TSI Conditioner workflow around plugin actions and artifact-based processing

### Added

- Added consolidated TSI Conditioner workflow for file, folder, detector result, and frequency-based inputs.
- Added plugin-action query, customization, execution, and stop controls for conditioner operations.
- Added schema-driven conditioner parameter controls and action details.
- Added IQ input previewing with configurable sample rate.
- Added conditioner results display, CSV export, and SOI promotion.
- Added artifact generation for raw IQ files, SigMF recordings, and ZIP bundles.
- Added selected-node conditioner status mirroring and progress reporting.

### Changed

- Replaced the previous Conditioner workflow with a unified selected-node workbench.
- Updated conditioner execution to support local and remote plugin actions.
- Updated input handling to resolve files, folders, detector results, and generated frequency selections consistently.
- Updated conditioner outputs to use operation-scoped artifact directories.
- Updated the Conditioner interface, styling, navigation, and node-selection behavior.

### Fixed

- Fixed raw IQ and SigMF ZIP bundle creation for file and folder inputs.
- Fixed conditioner status updates so action progress and node messages are reflected in the Dashboard.
- Fixed Conditioner initialization and reset behavior when selecting, removing, or changing sensor nodes.
- Fixed SOI promotion state handling after successful promotion.

## 2026-7-02

Rework TSI detector workflow around consolidated plugin-action controls

### Added

- Added consolidated TSI Detector workflow with Type, Mode, Hardware, and Action selection.
- Added plugin-action query/customize/start workflow for TSI detector operations.
- Added dynamic detector parameter controls populated from plugin action schemas.
- Added unified detector status card with selected-node status mirroring and operation state.
- Added shared TSI detector results handling for Fixed, Sweep, and future detector modes.
- Added unified detector raster plotting for live detector results.
- Added detector plot autoscaling based on active detector settings and observed detection data.
- Added shared green/red start-stop button styling for detector operations.

### Changed

- Replaced separate TSI Fixed and Sweep detector workflows with one consolidated detector workbench.
- Reworked detector action selection to use plugin action tags for detector type, mode, and hardware filtering.
- Updated detector execution to use the selected-node plugin-action path.
- Updated detector customization to render schema-driven parameters instead of hardcoded Fixed/Sweep controls.
- Updated detector result routing to use unified detector run state and operation IDs.
- Updated detector plotting to follow recent detection data while still using configured bounds before data arrives.
- Updated TSI hardware refresh handling to preserve detector selections during node status and CoT updates.
- Updated detector status handling to follow the top-panel selected node.
- Updated detector card stylesheet selectors for the consolidated layout.

### Fixed

- Fixed selected-node hardware refresh handling so TSI detector hardware options update correctly for the selected node.

## 2026-6-28

Improve TSI Fixed detector plotting and selected-node gating.

### Added

- Added a Fixed detector raster plot for visualizing detections by frequency and elapsed time.
- Added a Fixed detector unavailable-node state for when no online sensor node is selected.
- Added selected-node gating for Fixed detector controls to prevent starting detection without usable node hardware.

### Changed

- Reworked the Fixed detector blacklist as a Dashboard-side frequency filter for detector results, conditioner input, and plot updates.
- Reworked Fixed detector plotting to use plugin-action detection reports instead of the legacy wideband detector plot path.
- Updated Fixed detector plot styling for light, dark, and custom Dashboard themes.
- Updated selected-node cleanup so local and remote node availability changes refresh TSI hardware-dependent controls.

### Fixed

- Fixed Fixed detector results and plot updates not being scoped to the selected sensor node.
- Fixed stale Fixed detector controls remaining available after the selected node disconnected or was removed.
- Fixed local sensor node stop leaving node-dependent TSI controls populated with stale hardware.
- Fixed Fixed detector result clearing only clearing the table instead of also clearing plotted detections.

## 2026-6-27

Migrate fixed detector tab to plugin action workflow.

### Added

- Added .gitkeep to plugin hardware folders for iq_record and iq_playback.
- Added Fixed detector selected-node action launch support from the TSI tab.
- Added Fixed detector GUI/headless run mode selection for local nodes.
- Added throttled Fixed detector embedded-block detection output.
- Added Fixed detector result population for frequency, power, and time in the detector and conditioner tables.
- Added Fixed detector operation state tracking using operation IDs.

### Changed

- Removed Automation tab from TSI tab.
- Updated Fixed detector workflow to use Base fixed_detection plugin actions instead of the legacy detector launch path.
- Updated Fixed detector B2x0 flow graph layout under maint-3.8 b2x0 headless/gui folders.
- Changed Fixed detector default sample rate to 1 MSps.
- Changed Fixed detector minimum detection interval default to 1 second.
- Updated Fixed detector operation parameter handling for sample rate, threshold, gain, channel, antenna, run mode, and minimum interval.
- Updated Fixed detector detections to flow through normalized detection/CoT handling while still appearing in Tactical.

### Fixed

- Removed extra files in Plugins folder.
- Fixed counts for Alerts, Exploits, and Reports in Sensor Nodes tab.
- Fixed Fixed detector GUI/headless detection flooding by adding embedded-block and operation-level throttling.
- Fixed local node mode reporting so local-only GUI Fixed detector controls can be enabled correctly.

## 2026-6-26

Fixing installer style sheet bugs.

### Changed

- Updated Contributions section in the README
- Moved idea_list.md to ./docs/gsoc/2023_project_ideas.md
- Moved Base plugin detection flow graphs into GNU Radio version-specific `maint-3.8` and `maint-3.10` folders.
- Updated Base fixed detection, LFM beacon detection, and LFM beacon geolocation operations to resolve flow graph paths using the active GNU Radio maint version.

### Fixed

- Fixed missing installer operating system radio buttons after icon assets were moved from `docs/Icons` to `UI/Icons`.
- Updated plugin flow graph compilation to skip GNU Radio version-specific `maint-*` folders that do not match the installer target.

## 2026-6-25

Add Tactical SOI, target, and artifact row controls with artifact refresh and compact metadata styling.

### Added

- Added Node SOI row deletion and clear-row controls for removing local SOI table records and associated map pins.
- Added Node Targets row cleanup controls: delete row, clear rows, and keep selected.
- Added Node Targets refresh behavior to preserve the current shortlist when rows are already displayed.
- Added Node Targets refresh selection handling to restore the previous target selection or select the first row after a full reload.
- Added Node Artifacts refresh control to reload known artifact metadata for the selected node from the HIPRFISR artifact registry.
- Added Node Artifacts delete-row and clear-row controls for pruning the local Dashboard artifact view without deleting artifact files or registry entries.

### Changed

- Updated Node Targets to behave as a per-node working shortlist derived from the global Targets table.
- Updated Node Targets refresh to recalculate only currently displayed targets unless the table is empty.
- Updated Node Targets row cleanup to affect only the Node > Targets table, not the main Targets tab or global target records.
- Updated Tactical button enable/disable handling to include the new SOI and Node Targets row-management controls.
- Updated Node Artifacts refresh handling to repopulate locally cleared artifact rows from hub-tracked metadata.
- Updated Tactical button enable/disable handling to include the new Node Artifacts refresh and row-management controls.
- Updated Tactical Node tab and Targets tab detail panels with more compact, consistently spaced metadata text for better readability in the right-side Tactical panel.
- Removed old poetry.lock file

### Fixed

- Fixed IQ rename button string handling error
- Removed duplicate frequency parameter from the iq_playback action schema

## 2026-6-24

IQ Data plugin workflow and plugin folder cleanup.

### Added

- Added Base plugin IQ recording support through the new plugin action/operation path.
- Added Base plugin IQ playback support through the new plugin action/operation path.
- Added B2x0/B20xmini IQ record and playback flow graph support under maint-3.8 and maint-3.10 plugin flow graph directories.
- Added artifact-based IQ recording output under operation-scoped artifact folders.
- Added node-scoped artifact metadata for IQ record, photo, video, motion, and SOI capture outputs.

### Changed

- Converted IQ Data recording from direct Dashboard/runtime handling to the Base plugin operation workflow.
- Converted IQ Data playback from direct Dashboard/runtime handling to the Base plugin operation workflow.
- Hid unfinished legacy plugin manager, plugin, and operations tabs while plugin workflows are rebuilt around actions.
- Reworked Base and WiFi plugin actions/operations to run from the new plugin folder layout without install_files.
- Moved WiFi helper code under Plugins/WiFi/scripts/wifi_lib and static OUI data under Plugins/WiFi/resources.
- Standardized Base operation import/path handling with PLUGIN_ROOT and FISSURE repo root resolution.
- Updated GNU Radio operation pathing to load flow graphs from Plugins/Base/flow_graphs/... instead of operation-local paths.
- Improved operation status cleanup, callback isolation, and artifact/source metadata consistency.
- Updated external-tool operations to resolve executables with shutil.which() and cleanly drain subprocess stderr.

### Fixed

- Fixed IQ record/playback pathing for maint-3.8 and maint-3.10 B2x0 flow graph directories.
- Fixed IQ record stop behavior so completed recordings can still be registered as artifacts.
- Fixed IQ playback parameter/path handling for plugin-based selected-node execution.
- Fixed fixed_detection.py and scan_detection.py flow graph imports after moving generated flow graphs under flow_graphs/.
- Fixed classify_features_dt.py to load decision tree models from Plugins/Base/resources/decision_tree_models.
- Prevented the SOI classification chain from failing solely because classification was skipped or no model report was written.
- Fixed photo, video, and motion capture artifact metadata so Tactical can associate returned artifacts with the originating node.
- Fixed HackRF and RTL-SDR detector callback/reporting payloads for Tactical detection handling.
- Fixed plugin action routing for Base geolocation and WiFi operations after the plugin folder restructure.

## 2026-6-18

Add IQ artifact recording and fix Tactical node scoping.

### Added

- Added IQ Data tab artifact browsing for local artifacts under FISSURE/artifacts/<operation_id>/files/.
- Added IQ recording through the Base plugin action path instead of the old direct IQ flow graph start path.
- Added Dashboard-generated operation_id tracking so IQ Data only resets for recordings launched from that tab.
- Added artifact format selection for Raw IQ File and Zip Bundle.
- Added GRC Parameter block support for runtime recorder values such as filepath, frequency, sample rate, gain, antenna, channel, and serial.
- Added selected-node scoping for Tactical Node tab detections, SOIs, and artifacts.
- Added source-node tracking to Tactical artifact metadata using artifact `source_id`.

### Changed

- Changed IQ record output to write into artifact operation workspaces instead of the old IQ Recordings path.
- Changed IQ record completion handling to reset the Record button/status when the matching artifact arrives.
- Changed Stop behavior to cancel queued files while allowing the current file capture to finish cleanly.
- Changed artifact refresh behavior so IQ Data Artifacts updates after matching IQ record completion.
- Changed Tactical Node Detections, SOIs, and Artifacts tables to rebuild from global records when selecting a Tactical node.
- Changed incoming Tactical detection, SOI, and artifact handling to always update global stores while only updating visible Node tab rows for the selected source node.
- Changed Tactical artifact handling to treat `source_id` as the canonical source node identifier for node-scoped artifact display.
- Changed Node Artifacts behavior to show locally known artifacts for the selected node without automatically requesting additional remote artifact data.

### Fixed

- Fixed stale/wrong-node detections remaining visible after selecting a different Tactical node.
- Fixed stale/wrong-node SOIs remaining visible after selecting a different Tactical node.
- Fixed artifacts appearing in the Tactical Node tab when no node was selected or when a different node was selected.
- Fixed Tactical Node Detections clear behavior so it removes only detections for the selected node instead of clearing all global detections.

## 2026-6-15

Unify IP node heartbeat state and CoT publishing.

### Changed

- Unified IP sensor node position/status reporting under heartbeat-driven HIPRFISR node state updates.
- Moved IP node CoT/TAK track publishing from Sensor Node GPS updates to HIPRFISR heartbeat state.
- Updated selected-node Dashboard and Tactical indicators to show disconnected remote nodes.

### Fixed

- Prevented stale IP sensor node traffic from queueing while the hub is offline and flooding the hub after reconnect.
- Removed stale local node Tactical pins and ecosystem rows when local nodes are stopped.
- Prevented normal IP GPS updates from sending duplicate node track messages.

## 2026-6-12

Alert map controls and cleaning legacy workflows.

### Added

- Added Tactical tab alert plotting, plot-and-zoom, map removal, row deletion, and alert table clearing controls.

### Changed

- Cleaned up duplicate icon assets after migrating application icons to `UI/Icons`.
- Moved sensor node configuration presets from `fissure/Sensor_Node/Sensor_Node_Config` to `YAML/Sensor_Node_Config`.
- Removed unused legacy sensor node settings recall callback after consolidating settings return behavior under node selection.
- Removed obsolete SOI automation callbacks and related default configuration options.

### Fixed

- Prevented Tactical tab alerts from auto-plotting when received as non-pin CoT events.
- Allowed the `fissure-hiprfisr` command to launch the remote headless hub without requiring Dashboard auto-connect settings to be disabled.

## 2026-6-10

Node selection rework, selected-node configuration, Tactical tab integration, and hardware settings cleanup.

### Added

- Added global selected sensor node workflow for Dashboard operations
- Added Select Sensor Node and Configure Selected Node controls to the top bar
- Added selected-node settings recall and display for nickname, IP address, status, location, notes, GPS, and hardware
- Added simplified selected node configuration dialog with GPS source controls and hardware defaults
- Added selected-node helper utilities for local/remote status, network type, hardware settings, and Wi-Fi interfaces
- Added selected-node hardware display support for SDRs and Wi-Fi adapters
- Added Tactical tab integration for selecting nodes from map pins, tables, and node info panels
- Added Tactical target parsing for node UID, SSID, BSSID, RSSI, observation time, SOI, and artifact metadata
- Added support for action schema min, max, step, decimals, and options metadata in Dashboard parameter widgets
- Added explicit HIPRFISR and node IP address settings with automatic node IP detection for selected node display

### Changed

- Replaced fixed 5-node Dashboard selection logic with selected-node UID routing
- Updated tab operations to use selected node UID instead of fixed sensor node indexes
- Updated hardware combo boxes to populate from selected node settings instead of legacy per-tab hardware lists
- Updated Wi-Fi interface guess behavior to use selected node configuration instead of Dashboard-local iwconfig
- Updated Dashboard hardware combo box refresh behavior after node selection/configuration
- Updated selected node hardware display names to use hardware IDs with UID fallback when serial/IP/interface values are missing
- Updated local sensor node launch and stop handling for the new top-bar workflow
- Updated selected node configuration to use the new YAML hardware structure with SDR and Wi-Fi adapter defaults
- Updated dummy CoT type action defaults to reduce message volume during testing
- Updated parameter widget generation to support negative numbers and bounded numeric inputs
- Updated Sensor Node heartbeats to report the node IP address separately from the HIPRFISR connection address

### Fixed

- Fixed blank Tactical target fields when metadata existed in raw CoT XML
- Fixed target geolocation status parsing across geolocation_status and geolocate_status
- Fixed alert display labels to include node nickname with shortened node UID fallback
- Fixed script argument unpacking in Wi-Fi scan and alert flow graph after adding run_with_sudo

## 2026-5-29

New Tactical tab, TAK alerts without pins, fixing target list imports.

### Added

- Support for sending TAK alerts with and without pins
- Tactical tab with map pack viewing and download
- Widgets and functionality for Node, Targets, and Ecosystem controls and status
- Mobile Atlas Creator to the installer and menu
- Added tak and dashboard requester_types to messaging
- Added requester_uid to more of the messaging
- Added tak, dashboard, and broadcast routing for CoT messaging
- Base, WiFi, Dummy, and Mission-01 plugins

### Changed

- Updated target list import to report more optional protocol fields
- Replaced Automation tab with Tactical tab
- Removed Automation tab widgets and functions
- Removed startup automation mode logic

### Fixed

- Fixed target list imports in TAK for more of the optional fields

## 2026-3-24

TAK geolocation, multi-node actions, CoT logging, and plugin enhancements.

### Added

- python3-pyproj and python3-uhd dependencies to the installer
- LFM beacon transmit flow graph to standalone flow graphs
- Target patch functions from actions to the hub
- Support for specifying expected node hardware in YAML to be used by filtering in plugin actions
- Example target list YAML file for importing from TAK
- Optional CoT logging support for TAK replay
- CoT replay script for logged sessions
- Multilateration utility functions for the hub
- More TAK support for geolocation and multi-node actions
- Action filtering for target classification/keywords

## 2026-3-06

Installer fixes and data conversion fixes.

### Added

- ainfosec.dev link to README
- Select button for IQ Data > Convert tab to pick the current directory in the IQ Viewer to use as the output directory

### Changed

- tak_on_startup variable in the config YAML file now support strings and booleans

### Fixed

- Modified opencv installer dependency to use `opencv-python-headless<4.12` to prevent numpy 2.0+ from being installed
- Removed sudo from pip package installs
- Fixing the data conversion algorithms to convert between data types better
- Removed extra '&' in _slotMenuStandalone_ais_rx_demodClicked() flow graph filepath

## 2026-3-03

Support for TAK alerts and action input parameters.

### Added

- Default TAK CoT types for node idle/busy in FISSURE YAML file.
- Alert callbacks for populating tables in TAK
- Support for querying action parameters from TAK

### Changed

- Pulling status from GPS position reports instead of its own message

## 2026-2-23

Compile flow graphs for Plugins and TAK features for status and control.

### Added

- Compile flow graphs for Plugins folder installer option
- TAK receive code for refreshing status and stopping operations

### Changed

- Adjusted functions for GPS beaconing to support on-demand single message responses

## 2026-2-18

Mechanisms for adding targets and displaying status.

### Added

- Functions for creating new targets
- Operation callbacks for SOIs, status, and targets
- Import target lists from WinTAK stored at the HIPRFISR

### Changed

- Providing status and version info in GPS position updates

## 2026-2-10

SOI management and plugin operations fixes.

### Added

- Functions to update and store SOIs for TAK
- Functions to import a target list for TAK
- Applying database classification to SOIs at the HIPRFISR for TAK
- Zip function for creating SOI evidence as an artifact for TAK
- TAK callbacks for specific WinTAK button presses

### Changed

- Changing CoT type for events and populating lat/lon/alt in CoT

### Fixed

- Passing in the node UID to plugin start/stop actions
- Updating node read_hiprfisr_messages() to create a new task for plugin actions to avoid blocking stop command

## 2026-1-13

Fixing artifact download errors.

### Fixed

- Rewrote updateArtifact() to use valid Python syntax
- Updating utils init file to support importing artifact functions
- Removing extra quote in RTL-SDR installer verify line
- Installing new clang dependency with gr-ieee802.11

## 2026-1-12

Modifying TAK-HIPRFISR messaging and bug fixes.

### Added

- Added a wait option to run_plugin_operation to block on operations

### Changed

- Commented out the old low throughput TAK functions that do not lead to the consolidated TAK utilities
- Modified the TAK receive at the HIPRFISR to allow message parameters in the xml and avoid string parsing

### Fixed

- Python strip() filepath issues with the second installer script
- Meshtastic GPS beacon messages using new TAK functions
- Timing error when running operations complete too quickly which would prevent start/stop status updates from occurring 

## 2025-12-29

Updating OpenWebRX installer.

### Fixed

- Removing interactive installer for OpenWebRX and adding prints for password prompts.

## 2025-12-19

Updating the FISSURE plugin to TAK message chain to pass dictionaries.

### Added

- Added "iw" package to the installer
- hackrf_sweep and rtl_power detectors in the Tools folder for scanning specific frequency bands

### Changed

- Removed HIPRFISR TAK send code and replaced with utility calls in the callback functions.
- Renamed HIPRFISR callback for TAK messages to takReturn()
- Updated SensorNode.py send_tak_cot() to use a dictionary when accepting inputs from FISSURE plugins and sending to the HIPRFISR
- Updated GPS beacons and plugin querying returns to use new dictionaries for TAK messages

### Fixed

- Added support for optional dictionary fields in tak_messages.py utilities

## 2025-12-17

Updating TAK messaging.

### Added

- Added unified TAK message API supporting pin, event, and track message types
- Added structured XML payloads under "fissure" for plugin lists, actions, detections, SOIs, and targets
- Added automatic UID generation for event messages to prevent map icon conflicts
- Added tak_messages.py utility file for uniformity

### Changed

- Replaced remarks-based message parsing with structured XML parsing
- Using pytak for sending all messages to TAK
- Updated plugin_list and plugin_action responses to use new formatting

### Fixed

- Fixed malformed XML issues caused by manual CoT construction
- Fixed suppressed-point events appearing as pins on the map

## 2025-12-15

Fixing pytak installer and freezing bugs.

### Changed

- Installing pytak with sudo
- Removed pytak from TAK Server installation across all dependencies

### Fixed

- Adding pytak to the Misc. Dependencies for all operating systems
- Disabling auto connect to TAK server in the FISSURE config file to prevent freezing without a TAK server
- Unmerging IQEngine and TAK server installer items for Ubuntu 24.04
- Updating first TAK server connect try in HiprFisr.py so it no longer blocks on auto connect without a reachable TAK server 

## 2025-12-12

Simple database frequency lookup for protocols on alerts.

### Added

- Added a frequency_lookup table to the database. Columns: id, freq_low, freq_high, protocol_name, region, priority, notes
- Created a library utility function (classifyFrequencyFromTextDirect) which takes in text with a frequency unit or alert text following a pattern and returns the first table match in bounds with the highest priority
- Created a common utility function that converts CoT UID text to a frequency string with a label (extractFrequencyFromUID)
- Updated these functions to classify signals from frequency: alertReturn, alertReturnLT, takPlot, takPlotLT

## 2025-12-08

Headless HIPRFISR bug fixes.

### Added

- Pull request #103: Fixed sensor node alert sender IP vs. Meshtastic message fields
- Added fissure_install.log to .gitignore
- Ignoring unapproved plugins via .gitignore

### Changed

- Renamed installer.log to fissure_install.log and placed in Installer folder during install

### Fixed

- Adding checks for dashboard_connected with the dashboard socket in HIPRFISR code to prevent freezing with headless HIPRFISR
- Removed creation of Install_Log folder during install
- Local sensor nodes set their nickname to "Local Sensor Node" in SensorNode.py

## 2025-12-07

Meshtastic networking overhaul.

### Added

- Pull request #102: Hiprfisr logging
  - Hiprfisr logging of received sensor node heartbeat
  - Fixed HIPRFISR TAK plot messaging incorrect use of UID
- Assigned short-ID system with hub-managed ID counter
- Complete Meshtastic handshake flow
- Reverse lookup helper: resolve UUID from assigned_id
- Persistent UUID-based log identifier for sensor nodes
- Meshtastic-safe last-seen tracking (no disconnect toggling)
- Integer validation/cast for sn_assigned_id
- Updated routing to support assigned_id as message SOURCE

### Changed

- Removed SensorNode class and associated functions in HiprFisr.py
- Reworked Meshtastic node registration logic (new vs. existing node behavior)
- Overhauled heartbeat handling: Meshtastic nodes no longer treated like IP nodes
- Updated send_msg behavior to use assigned_id instead of legacy identifier
- Dashboard mapping updated to rely strictly on UUID references
- Refactored node update paths for consistent state management
- Removed dependence on sn_int for RF timing; Meshtastic interval ignored
- Standardized node identity model (uuid = permanent, assigned_id = routing, identifier = logging)

### Fixed

- pingIP() now acquires the IP address using the UUID and the nodes dictionary
- Log identifiers regenerating randomly instead of matching persisitent UUID

## 2025-12-02

Adding callsigns to TAK CoT messages and using long UUID for IP nodes.

### Added

- Callsign prefix in YAML config file for CoT messages

### Changed

- Removed UUID from message envelopes coming from sensor nodes
- Set IDENTIFIER constant to UUID value in sensor nodes
- Using 8 character identifier for Meshtastic connections
- Inserted uuid variable into all HIPRFISR callbacks as part of read_sensor_node_messages()
- Removed uuid from message PARAMETERS coming from the sensor node since it is in the identifier

### Fixed

- Added checks to exit the connect loop and not print warnings continuously when running a headless HIPRFISR
- Removed resolving identities from Dashboard mappings for TAK operations

## 2025-12-01

Switching IP node connection to ROUTER-DEALER and fixing shutdown procedures.

### Added

- Replaced ZMQ PAIR with ROUTER-DEALER
- HIPRFISR/hub no longer sends heartbeats to nodes
- Nodes send more information in heartbeats
- HIPRFISR/hub maps dashboard slots to node UUIDs and stores node info by UUID
- Message from nodes contain UUID
- New Dashboard widgets for connecting to sensor nodes
- Code in README for killing all FISSURE related programs in one line
- Added more password prompt exceptions to the list

### Changed

- Changed default remote sensor node heartbeat and message ports to 6100 and 6101 to not overlap with HIPRFISR ports when sharing an IP
- Heartbeats transmit their interval in each message
- Sensor Node reads its config file for heartbeat_interval
- UUID is written to a file in ~/.fissure directory for local and remote nodes

### Fixed

- Revamped shutdown and task cleanup
- Error in operations.py when not passing in all the expected arguments
- Added aircrack-ng from source to installer for raspberry pi setups
- Simplified hardware select dialog functions that listed all widgets for every tab

## 2025-11-12

Adjusting GPS behavior, adding saved and internet GPS source options.

### Added

- Saved and Internet options for gps_source in sensor node config file
- Internet option for Find button in sensor node configuration dialog
- Pull request #101: TAK plugin interaction functionality
  - Moved TAK server connection to Hiprfisr init.
  - Added TAK to Sensor Node plugin names query functionality.
  - Removed legacy test plugins.
  - Wifi plugin updated: TAK integration ready, channel switching bug fixed, automatic device selection
  - TAK FISSURE plugin operation fully functional.
  - Resolved merge conflicts.
  - Removed pytak increased tx queue size that held messages to TAK server.

### Changed

- Put a lock around accessing the Meshtastic serial port for Find button and beacons
- No longer passing in current position into GPSManager, handling all position updates in gpsUpdate callback
- Moved Ping button from remote actions to local actions in sensor node configuration dialog
- Added a % to the end of CPU button return value

### Fixed

- Meshtastic GPS source (for new temporary Meshtastic serial connections) option now works for remote IP networking, updated beacon and findGPS_Coordinates
- Sensor node no longer crashes if Meshtastic GPS probe does not return a position during Find
- Remote IP Address Ping returns values after connected to a remote node
- Created missing memoryIP_Return, diskIP_Return functions in Dashboard callbacks

## 2025-11-05

Fixing auto-connect to TAK server and suppressing warnings.

### Changed

- Updated TakReceiver run() to loop continuously to work with new connect behavior

### Fixed

- Pull request #99: Adding fixes to TAK logic for fresh OS boot and reconnects
- Updated HiprFisr.py begin()/event loop with new connections to pytak and reconnect behavior with TAK connect_mode set to auto

## 2025-10-29

Dashboard connection and logging fixes for a remote HIPRFISR.

### Fixed

- Merging pull request #98: `For compatibility with <Python3.10 changed instances of parameter definitions in format type1\|type2 to format Union\[type1,type2\].`
- Updating FissureZMQNode.py to perform safe logging during shutdown to suppress warnings
- Adding a sleep line to prevent warnings during shutdown in backend event loop
- Resetting Dashboard states when disconnecting from HIPRFISR to enable UI widgets on reconnect
- Commented out async function calls in LibraryTabPluginManagerTabSlots.py in connect_slots() that were called too early in the Dashboard startup
- Dashboard disconnects from HIPRFISR instead of shutting down the HIPRFISR for a remote HIPRFISR

## 2025-10-28

Fixes for connecting to remote HIPRFISR.

### Added

- Added new image in README under Key Capabilities

### Changed

- Removed "server" variables from YAML config files
- Added "--remote" argument to fissure-hiprfisr command
- Changed default remote IP address hint from "127.0.0.1" to "192.168.1.xxx"

### Fixed

- Commented out IP address update in HiprFisr.py initialize_comms()
- Fixed connect() in StatusBarSlots.py to perform connect_to_hiprfisr() without errors

## 2025-10-26

Fixes for standalone HIPRFISR testing.

### Added

- fissure-hiprfisr command to the installer for launching the HIPRFISR and processing engines without the Dashboard

### Changed

- Updated all fissure Command installer items to match Ubuntu 24.04 installer
- Updated interactive roadmap with search and list of immediate children

### Fixed

- Fixed wget filepath error for 5 MS/s online archive IQ files
- Increased range values for decimation and center sliders in demodulation tool
- Increased the number of digits for center and threshold sliders in demodulation tool

## 2025-10-23

Merging pull request #97, fixing Apptainer install.

### Added

- Merging pull request #97: 
  - Fixed issue in wifi plugin wifi_scan_ap where monitor mode disabled during scan
  - Added functionality to stop all plugin operations on a sensor node

### Fixed

- Creating .local/bin folder for fissure-apptainer command and adding the path to .bashrc
- Fixed Wayland GUI launch issue by binding `$XDG_RUNTIME_DIR` to a writable `/tmp` path inside the Apptainer, allowing Qt5/XWayland to initialize properly when running in headless writable containers
- Adding `--no-sandbox` to chrome command in Apptainer %post

## 2025-10-22

Apptainer containerization updates.

### Added

- install_apptainer.sh script for configuring containerization with Apptainer
- fissure-apptainer.sh template for executing a new apptainer terminal shortcut
- fissure_apptainer.def for managing the apptainer build
- helpful_apptainer_commands.txt for reference

### Changed

- Modified Ubuntu 24.04 installer for Apptainer containerization

### Fixed

- Adjusting bit extraction technique in the demodulation tool to match the plot window samples using midpoint sampling
- Restoring line-buffered mode in the installer by calling the second script with `python3 -u`

## 2025-10-16

Preparing installer for containerization.

### Changed

- Merging pull requests #94, #95, #96

### Fixed

- Removing first installer script prompts from headless install
- Running second installer script as an executable instead of with Python

## 2025-10-15

Adding headless installer and deployment modes.

### Added

- Headless installer for operating systems and modes for FISSURE deployments
- Buttons in installer GUI for recalling modes for Full (previously Default), HIPRFISR, Dashboard, and Sensor Node

### Changed

- Renamed "Default" button in installer to "Full"

## 2025-10-15

Cleaning installer code.

### Changed

- Removed code from OS installer files
- Updated labels for first installer GUI
- Removed programs from second installer script
- Pointed first installer script to call second installer script instead of OS installer files
- Updated installer info in the README

## 2025-10-14

Fixing pytak import errors on install and sample offset slider in demod tool.

### Fixed

- Moving pytak imports away from the start of the HiprFisr.py
- Adding sample_offset to plotting function in demod tool
- Removing extra disk_usage.txt file in Installer folder

## 2025-10-13

Adding simple FM demodulation tool in IQ Data tab.

### Added

- Demod button and dialog in IQ Data tab for obtaining bits from signals
- Function for initializing tab indices on Dashboard launch

## 2025-10-06

Updating README roadmap and white papers.

### Added

- Interactive roadmap link and current priorities in README Roadmap section
- FISSURE white papers and updated links in README White Papers section

## 2025-10-02

Merging pull requests #86-#90, #92: TAK, plugins, GPS, and Raspberry Pi updates.

### Added

- Update hardware.py #88
  - Update to gpsd receive to not kill and restart the service on each read attempt
- Tak integration #89
  - TAK server module added
  - Hipfisr TAK server monitor interface added
  - Hipfisr send_cot now accepts TAK type string
  - Beacon stale time changed to 60 seconds instead of 60 minutes
  - Beacon cot message switched to provide track
- Sensor node updates #90
  - Sensor node updates based on Raspberry Pi 4 Ubuntu 24.04 installation and operation as a sensor node. TPMS, Wifi AP detection and Wifi reboot playlists included for reference. Alert sender handling of types in TAK messages added.
  - TPMS alert: dropped snreport, added type to TAK report
  - Wifi AP finder and autorun playlist added
  - Added iwlist to password exception commands
  - Added raspberry pi remote sensor node config for reference
  - Alert sender now handles type arguments on TAK messages
  - Added wifi reboot autorun playlist
- Fixed error on fissure dashboard launch if fissure-plugin-editor is n… #92
  - Fixed error on fissure dashboard launch if fissure-plugin-editor is not found
- TAK connect_mode variable in config files to choose auto/manual/disabled for connecting the HIPRFISR to a TAK server
- TAK menu for starting/stopping a local TAK server and for connecting/disconnecting to a TAK server (preconfigured in YAML config files)

### Changed

- Moved TAK menu items from Tools to TAK
- Updated README with videos, intros, diagrams, white papers, blog posts, TAK setup, testimonials

### Fixed

- Made config file checks to determine if the HIPRFISR should connect to a TAK server on boot

## 2025-8-03

Fixing remote IP actions.

### Fixed

- Correcting sockets used for remote IP actions in HiprFisrCallbacks.py
- Changing typo for backend function from "ifconfigprocessesIP" to "ifconfigIP"
- Disabled/enabled network type combobox on IP connect/disconnect in sensor node configuration dialog

## 2025-7-30

Merging pull request #85: Fixing gpsd

### Changed

- Created more password prompt exceptions used in remote sensor node commands

### Fixed

- Stopping gpsd service when probing a GPS device on a specific serial port and killing gpsd when done

## 2025-7-23

DragonOS Noble installer fixes, ifconfig and iwconfig remote actions

### Added

- Software sizes for DragonOS installer items
- ifconfig and iwconfig remote actions for sensor nodes

### Changed

- Updated README to remove git submodule lines from the installer

### Fixed

- Ubuntu Noble APT Sources installer item for DragonOS

## 2025-7-22

DragonOS Noble beta and installer updates.

### Added

- Sensor node button in the installer for selecting default items needed for remote sensor/tactical nodes
- Beta support for DragonOS Noble (24.04) (replacing FocalX, FocalX installer items are still in the installer file and can be uncommented to use)
- gr-sidekiq OOT git submodule and installer item (maint-3.10)

### Changed

- Replaced checks for DragonOS Focal and FocalX with DragonOS

### Fixed

- Updating installer to grab the latest branch commit for all GNU Radio out-of-tree modules

## 2025-7-21

More remote actions for sensor nodes.

### Added

- Querying the sensor node to report uptime, memory usage, disk usage, CPU percentage, processes, and reboot

### Fixed

- PlutoSDR installer for Raspberry Pi OS and Ubuntu 24.04
- Ignoring /dev/ttyS* ports when scanning for local meshtastic ports, only filtering for ttyACM and ttyUSB
- Disabling the network type combobox when connected so the user can't switch between types, enabling after disconnect

## 2025-7-15

Fixing installer for password prompt exceptions.

### Fixed

- Changed "USER_NAME" to "USERNAME" in password prompt exceptions template to allow sed command to work for $USER

## 2025-7-11

Preliminary support for CaribouLite.

### Added

- Preliminary support for CaribouLite

### Fixed

- Stop button now halts autorun playlist before repetition interval pause
- Recompiled RTL2832U fixed threshold detector to get rid of SDRplay artifacts caused by unintential overwriting
- Updated Raspberry Pi installer to replace tensorflow-cpu package (does not exist) with tensorflow
- findRSPdx now returns RSPdx instead of RSPdx R2

## 2025-5-21

Merging pull request #84: Meshtastic GPS reading from log to fix stale reading issue.

### Changed

- Reporting back cached GPS values for Meshtastic and providing warnings with stale time since last acquisition

### Fixed

- Updating Find/Beacon GPS values for Meshtastic to use the logs and not MyNodeInfo
- Adding missing re python package in FissureMeshtasticNode.py
- Improved error handling when GPS is not acquired from Meshtastic device

## 2025-5-02

Sensor node auto-launch option, installer and other fixes.

### Added

- Auto-Launch Sensor Node installer item option to run fissure-sensor-node in a terminal on boot

### Changed

- Adding shebang to top of fissure-sensor-node command in installer
- Updating HackRF version to 2024.02.1

### Fixed

- Updating FISSURE Infosheet link in README for new content
- Monitoring/printing errors while running scripts in alert_sender.py
- Replacing "user" with keyword from password_prompt_exceptions.txt
- Putting psycopg2-binary and python-dotenv in Misc. Dependencies for sensor node installs without the database
- Applying set_channel() and set_freq() with the network interface on in Wifi_Exploit_Finder.py attacks
- Replacing username in flow graph filepaths when running scripts on remote sensor nodes
- Popup windows in Sensor Node Configuration dialog now close properly
- Start TAK docker containers on launch works for TAK containers named after different versions
- Feeding logger into SensorNodeTracker() in HiprFisr.py to prevent errors
- Updating CMakeLists.txt across many installer programs to fix cmake 4.0 errors

## 2025-4-17

Adjusting monitor mode tool, attacks, and demo files.

### Added

- maint-3.10 demo plugin example

### Fixed

- Refactored Monitor Mode Tool to detect operating system and use appropriate command sets
- Fixed Wi-Fi Exploit Finder attack error from missing run_with_sudo variable
- Updating DIR-815 Exploit to Python3 in database
- Changing payload hex string for DIR-815 Exploit maint-3.10 attack
- Setting TP-Link Archer A7 attacks to not run with sudo
- Setting application name and desktop file name in \_\_main\_\_.py

## 2025-4-16

Demo support files and alert sender fixes.

### Added

- John the Ripper example in Tools>Data
- Demo support files
- D-Link DIR-815 Expoit attack

### Changed

- Adjusted TP-Link Exploit attack to have wget command example, better print statements, lander filename variable, faster intervals
- Renamed _slotMenuTAK_StopDockerContainersClickedClicked
- Changing all pkill commands to sudo pkill in SensorNode.py to help with scripts requiring sudo
- Adding run_with_sudo variable to Wi-Fi attack scripts

### Fixed

- Tracking alert_sender objects in SensorNode.py to close properly on attack stop
- Killing child processes when alert sender is stopped

## 2025-4-10

Fixes for plugins.

### Added

- Refresh button in Library > Browse tab for updating Dashboard database cache and widgets

### Changed

- Merging pull request #83: Update docker-compose.yml to fix CVE-2025-2945

### Fixed

- Apply changes, delete plugin in Library > Plugin Editor tab refreshes database cache and widgets
- Disabled functions checking plugin names at the sensor node that were unintentionally writing to the database
- Plugin export saves the inner folder with the new name

## 2025-3-31

Tracking sensor node position in WebTAK.

### Added

- Sensor node tracker class in HIPRFISR

### Changed

- Moving tak_send.py code from callbacks to HiprFisr.py
- Removed tak.exp

### Fixed

- Resize columns to contents in exploit table
- Adding sleep after transmitting a message in Meshtastic send_msg() to avoid crashing serial connection
- Fixing QTableWidgetItems in exploitReturnLT()
- Adding --no-check-certificate to remove error when downloading IQ files/collections from online archive

## 2025-3-27

Merging pull request #82: Flat file reporting

### Added

- Placed note in README that Ubuntu is the most tested operating system
- Reports tab for structured message returns to FISSURE
- Save button for Reports tab
- Resizing Reports table rows to contents

### Fixed

- tuple/Tuple error in common.py
- Added tshark, ip to password prompt exceptions list
- Copied the updated 3.10 Python attack scripts to the 3.8 library directory
- Fixing nested quote errors in Wifi_Scan_and_Alert.py and Wifi_Exploit_Finder.py
- Copying resources folder from maint-3.10 single stage attacks to to maint-3.8
- Fixing Wi-Fi Scan and Alert and Exploit Finder returning multiple power values that impacted message parsing

## 2025-3-22

GPS TAK beacon feature.

### Added

- GPS TAK beacon functionality
- IP and Meshtastic functions for passing GPS TAK beacons from Sensor Node to TAK
- Buttons in sensor node configuration dialog to enable/disable the GPS TAK beacon for IP and Meshtastic network types
- gps_tak_beacon option in sensor node configuration file

### Fixed

- Probing gpsd now checks for the serial connection and quickly times out if there is no GPS lock to help prevent freezing
- gpsd serial port correctly passed into GPSManager object
- Changing Meshtastic Info popup parent to sensor node configuration dialog
- Find button returns None for the location and re-enables the Find button when an error occurs while probing gpsd
- Removed process errors for attacks when stopping an autorun playlist
- Preventing multiple instances of FISSURE from running on the same computer with the fissure command

## 2025-3-20

Fixing receiving functions for Meshtastic network node.

### Fixed

- Removing recv_msg() from FissureMeshtasticNode() and calls inside receive loops (it polls on its own)
- Connecting to remote sensor node over IP with "local" set in sensor node config file and recall settings on connect checked no longer shows up as local on connect button click

## 2025-3-16

gr-fuzzer fix for maint-3.10, TAK installer fixes

### Fixed

- Imports in maint-3.10/gr-fuzzer blocks.yml files changed to "import gnuradio.fuzzer as fuzzer"
- Changing ownership from root to user for certificate in TAK installer
- Adding docker IP address acquisition to all operating systems in TAK installer
- Ignoring Wayland warnings when changing the main menu items
- Checking for certificates folder when launching FISSURE

## 2025-3-14

Updating TAK send functions for async messaging.

### Changed

- Updating TAK send functions for async messaging

## 2025-3-13

Low throughput callbacks for alerts.

### Added

- Low throughput functions and codes for alert, tak plot, and exploit returns
- Start/Stop TAK docker container menu items
- alertReturn, takPlot, exploit low throughput callbacks and codes

### Fixed

- Changed permission level for certain TAK certificates from root to user
- Removed extra DIR-815 Python2 attack in database
- Improved error handling when online archive files cannot be reached, using asynchronous functions

## 2025-3-12

Merging pull request #79 and bug fixes.

### Added

- Added more installer notes to README
- Merging pull request #79: "Exploit detection/messaging infrastructure and UI features"
- Sensor Nodes>Exploit tab

### Changed

- Updated database dump with exploit attacks/scripts

### Fixed

- Removed sudod typo in TAK Server installs
- probeMeshtasticGPS no longer hangs when there is no GPS lock 
- Adding libpulse-dev to GQRX install

## 2025-3-10

Fixing flow graph errors and TAK Server installer.

### Fixed

- overwriteFlowGraphVariables() can handle empty strings, fixes Archive Replay start button and other actions, broken after fuzzing fixes commit
- Removing extra ip_address variable when starting Archive Replay
- Added eventlet package to installer for tak_send.py

## 2025-3-09

Updating TAK Server installer, downloading git submodules for OOT modules if missing

### Changed

- Updating the TAK installer with direct commands for installing with docker
- Downloading git submodules for out-of-tree modules during install if not downloaded already

### Fixed

- Filling the FISSURE config files with the TAK webadmin_cert during install
- QtDesigner install for Ubuntu 24.04
- Adding sudo to TAK Server docker commands to avoid errors from no restart/refresh of docker user permissions
- Checking if unzipped TAK Server docker folder exists before doing the install

## 2025-3-06

Updating TAK Server installer for testing.

### Added

- WebTAK menu item in Tools > Mapping

### Changed

- Updating TAK Server installer for testing

### Fixed

- Run with sudo set to False by default for Python attacks, checks in file to make it True

## 2025-3-05

Sensor node configuration GUI and field fuzzing fixes.

### Added

- Probe function for 802.11x devices (iwconfig)
- pkill added to password prompt exceptions
- getFieldDataAll() library function

### Changed

- Popup when querying remote sensor node status over Meshtastic 
- Editing async_ok_dialog to have a scrollbar and follow style sheets
- Removed getFieldProperties() library function, not in use
- overwriteFlowGraphVariables can save variable values starting with double quotes (for quoted dictionaries "{}")
- Updated fuzzing flow graphs and fuzzer block to accept database information
- Updated AttackTabSlots.py to feed database information to sensor nodes when fuzzing fields

### Fixed

- Sensor Node Configuration init() opens to the right disconnect stacked widget
- Calling local and remote slot functions on Sensor Node Configuration init() and disabling local button if already configured
- Autoscan and guess return 802.11x interface names for interfaces in monitor mode
- Bottom widgets are hidden on Sensor Node Configuration init() before connecting to/launching a sensor node
- Fuzzing flow graphs now reference database packet type field values instead of the old library yaml file
- Updated IQEngine button in IQ Data tab to use port 3001

## 2025-3-04

Updates to low throughput network connections for remote sensor nodes.

### Added

- Guess button functions and messaging for meshtastic connections
- HeyWhatsThat Path Profiler to Tools > Point-to-Point
- Windy Route Planner to Tools > Point-to-Point (click "Distance & Planning" from Windy menu)
- Windy to Tools > Weather
- Functions in Frontend.py for enabling/disabling widgets when switching between high throughput and low throughput sensor nodes

### Changed

- Added Stop button for Sensor Nodes > Autorun tab

### Fixed

- Sensor Node Configuration dialog Apply button saves Meshtastic serial port and baud rate, network type
- Sensor Node Configuration dialog recalls network type and Meshtastic settings
- Replaced instances of sensor node setting "serial_port" with "meshtastic_serial_port"
- Adding meshtastic_serial_port, meshtastic_serial_baud_rate, network_type variables to FISSURE config files under each sensor node

## 2025-3-03

Packet Crafter fixes and updates.

### Added

- Import and Export buttons to Packet Crafter

### Changed

- Data for UDP packets in Attack>Packet Crafter tab changed from String to Binary/Hex, edited AttackTabSlots.py to support hex strings and "\xFF\xAA" strings
- Modified UDP packet types in FISSURE database to support binary/hex

### Fixed

- Changing protocol to/from 802.11x toggles "Calculate CRCs" and "Assemble" button visibility
- "Restore Defaults" button in Packet Crafter is tied to the right callback function

## 2025-3-02

Scan and probe functions for Meshtastic connections

### Added

- Scan and probe functions for remote connections with Meshtastic
- closeEvent() function to HarwareSelectDialog.py

### Changed

- Moving hardware probe actions to utiliy functions in hardware.py
- Replaced HardwareSelectSlots.py cancel() function with closeEvent()

### Fixed

- Starting local sensor node and closing Dashboard with the 'X' before clicking apply gives warning to prevent hanging on close

## 2025-2-28

Fixing GPS acquisition, adding password prompt exceptions.

### Added

- Password Prompt Exceptions to the installer to ignore prompts at remote sensor nodes
- password_prompt_exceptions.txt in the Installer folder, gets copied to /etc/sudoers.d/fissure
- Test & Measurement Fundamentals YouTube playlist from Rohde & Schwarz to Lessons menu
- ACARS Hub live map to Tools>Aircraft>Trackers menu
- Adding Alert Listeners to News in README

### Changed

- FissureMeshtasticNode.py updates to support GPS acquisition

### Fixed

- Finding GPS in sensor node configuration returns 2D lat, lon values for all formats and methods
- Nickname from sensor node config file no longer shows up for a local sensor node
- Launching, disconnecting, repeat for local sensor nodes now shuts down HIPRFISR connections

## 2025-2-27

Adding sensor node command to installer; Merging pull requests #73, #74, #76.

### Added

- fissure-sensor-node command to the installer for launching the remote sensor node code on a computer
- IEEE OUI List in tools menu
- msgpack to the installer
- #74: Adding TAK to installer

### Changed

- Updating FissureMeshtasticNode.py code still under test
- Changing sensor node command in README
- #73: TAK startup options in config files, function in Hiprfisr.py for starting TAK docker container
- #76: Updating TAK attack scripts and TAK related callbacks

### Fixed

- Fixed broken link for Sanitized IEEE OUI Data
- Changing IQEngine local docker port to 3001 to avoid conflicts with pgAdmin 4

## 2025-2-24

Merging pull requests #71 (Tak server options) and #72 (Alert sender updated to use gpsd).

### Changed

- Updated config files and options dialog with TAK settings from pull request #71 "Tak server options"
- Updating sensor node code and alert utilities to work better with gpsd from pull request #72 "Alert sender updated to use gpsd"

## 2025-2-23

Listeners tab for alerts, run autorun playlists as stored.

### Added

- Created widgets and messaging to run autorun playlists as stored on the sensor node from the Autorun tab
- Added "Sensor Nodes > Listeners" tab to enable alternative communication channels for receiving alerts at the HIPRFISR, supporting Meshtastic, ZMQ SUB, Website Poller, Serial Port, TCP/UDP, Filesystem, and MQTT listeners
- Added python packages to Misc. Dependencies throughout the installer: watchdog, aiohttp, paho-mqtt
- Added alert listener test scripts in Tools folder
- SOF Week to upcoming events in README

### Changed

- Repositioned functions in HiprFisrCallbacks.py

### Fixed

- Adding scrollbars to alerts table
- Changing synchronous error messages to asynchronous in _slotSensorNodesAutorunStartStopClicked()

## 2025-2-19

Adjusting Sensor Node Configuration dialog buttons and code.

### Added

- "Rows → All" button in Sensor Node Configuration dialog
- Merging changes for "Update options.ui" pull request
- Merging changes for "Tpms hackrf recieve no sudo" pull request

### Changed

- "Add to All" button renamed to "Row → All"
- Consolidating HardwareSelectSlots.py and HardwareSelectDialog.py functions to use less code

## 2025-2-18

Merging and adjusting the pull request for alert updates.

### Added

- Calling attack scripts at the sensor node with the new alertSender class
- Updating alertReturn() callback and adding takPlot() callback in HIPRFISR
- Adding alert_sender.py to utils folder
- TPMS receive scripts for testing alerts
- Wi-Fi scanning script for testing alerts
- Placing alert count in Sensor Nodes tab in addition to Alerts tab

## 2025-2-17

Hardware utility functions for gain, antennas, and channels.

### Added

- Disabling Archive>Playback Start button when no transmit antenna is available
- Toggling Archive>Playback enable controls during operation
- Adding utility functions in hardware.py: getHardwareAntennas(), getHardwareChannels(), getHardwareGain()

### Changed

- Acquiring hardware gain, antenna, channel values from utility functions
- Changing bladeRF 2.0 frequency range to 70-6000 MHz
- README cloning instructions updated for clarity

### Fixed

- Disabling playback for SDRplay SDRs
- Selecting receive-only hardware in Playback tab no longer disables hardware selection combobox
- Removed some of the debug prints in the library functions
- Updating AIS talent community link in README

## 2025-2-16

Updating bladeRF 2.0 flow graphs with Soapy blocks.

### Changed

- Default gain values for bladeRF2 for maint-3.10 flows graphs/operating systems in Dashboard

### Fixed

- bladeRF2 waterfall acquires the correct filename from the database
- Updated bladeRF2 flow graphs with Soapy source/sink blocks

## 2025-2-14

Plugin updates and FISSURE Capabilities document

### Added

- FISSURE Capabilities PDF (11Sep24) to Help menu and README
- Plugin import function to load in ZIP file plugins with and without a password
- Added p7zip-full to the installer

### Changed

- Resizing README install1.png image to be smaller

### Fixed

- Updating create plugin function to open the newly created plugin

## 2025-2-13

Networking and GPS updates, Meshtastic integration (Part 1)

### Added

- Meshtastic item to installer under Minimum Install
- MeshMap link in Tools menu
- GPS source option when acquiring location in Sensor Node Configuration
- IP/Serial option when connecting to a remote sensor node
- Added serial_port, serial_baud_rate fields to sensor nodes in FISSURE config files
- GPS acquisition options at sensor node using the config file, automatically on startup, and updates at a periodic interval
- xdg-utils to the installer

### Changed

- Consolidating local(), remote() functions in HardwareSelectSlots.py
- HIPRFISR network nodes initialized to None instead of SensorNode()
- HIPRFISR network nodes closed with new function instead of relying on \__del\__
- Moved BANNED_MESSAGE_TYPES list to common.py
- Removed local, remote example sensor node YAML configuration files, added more comments in default.yaml
- Changing the database port to 5431 to avoid conflicts with other programs

### Fixed

- Adding missing version parameters to addAttack and addDemodulationFlowGraph in HiprFisrCallbacks
- Deleting (some of) the associated attack files when removing rows from the Browse "attacks" database table
- Corrected for lower case heartbeat messages when filtering for heartbeats in Log tab

## 2025-2-03

Kali/Kali Rolling installation fixes 2.

### Fixed

- Adding sudo apt update to start of install script
- Adding missing word in README
- Adding libzmq3-dev, zstd to Kali installer
- Enabling dump978, OpenCPN, Arduino IDE, RTLSDR-Airband in Kali installer

## 2025-2-02

Kali/Kali Rolling installation fixes 1.

### Changed

- Removing version from docker-compose.yml to prevent warnings

### Fixed

- Moved install script items to their own lines to prevent complete failure for OS updates
- Adding Python2 to the Kali installer
- Replacing killall command with pkill in GNU Radio installation in the Kali installer
- Changing docker-compose-v2 in the Kali installer for database installation
- Making docker start on boot for Kali

## 2025-2-01

Qt scaling options and remember configuration fixes.

### Added

- Unregister commmand for removing a WSL2 distribution in README
- Global scale factors in View and Options menus for setting QT_SCALE_FACTOR (>=1.0). Must restart FISSURE to see changes.

### Changed

- Removing prompt from Xasitr install items
- Installing VLC with apt instead of snap
- Reworded README text
- Disabling ESP32 Bluetooth Classic Sniffer in menu and unchecking it in installer items (needs fixes for newer Wireshark versions)

### Fixed

- Ceiling fan lesson not opening from menu
- Remember Configuration not writing to file on close, Frontend was closing before Backend completed shutdown
- Remember Configuration not saving to Backend settings on check/uncheck preventing saving on close
- Removing parameters for banned message types in logging when executing callbacks

## 2025-1-31

Querying sensor nodes for GPS coordinates and mapping results.

### Added

- Find, Map buttons to Sensor Node Configuration dialog for querying GPS receivers and opening locations in default KML viewer
- GPS utility functions for converting between formats
- Hardware probing functions for acquiring GPS coordinates from gpsd
- mgrs to the installer
- GPS Acquisition and mapping to News section in README
- Career fair event in README

### Changed

- Replaced inline slot functions for selecting new plugin supporting files in the tables
- Changed installation steps for blaze in m17-cxx-demod
- Using default options for Kismet installation

### Fixed

- Loading a new plugin supporting file populates text in the correct row and table
- Added Blaze libraries to all m17-cxx-demod installer items

## 2025-1-27

WSL2 adjustments and suppressing installer prompts.

### Added

- Bluesky link to README

### Changed

- Adjusting "Deployment Configurations" image size limits in README to prevent rescaling the aspect ratio

### Fixed

- Adding ubuntu-standard, eog to Ubuntu installations
- Installing opencv-python-headless instead of opencv-python to fix WSL2 errors
- Fixed pip items without --break-system-packages for Parrot OS installation
- Forcing package installation for monitor_rtl433
- Removing python3-cryptography before installing PyGPSClient
- Suppressing user inputs for tshark (Wireshark), Wifite2 (macchanger), rehex (cpan Template)

## 2025-1-25

Updating the installer and README.

### Added

- unzip, usbutils packages to installer
- FISSURE Deployments image in README and supporting text
- Added a note about GitHub releases in the README
- Windows 11 WSL2 Instructions in README

### Changed

- srsRAN install changed to srsRAN_4G
- SigDigger install changed from blsd to AppImage
- Switching from GPU version of tensorflow to CPU version in the installer

### Fixed

- SdrGlut install updated
- Made "Loading..." text wider in splash screen to prevent 'L' from being cut off

## 2025-1-22

Adding Alerts tab.

### Added

- Sensor Nodes>Alerts tab
- Alerts checkbox in Log tab
- alertsReturn() in DashboardCallbacks.py

### Fixed

- Fixed FISSURE Challenge image link in README

## 2025-1-20

Updating FISSURE Challenge text in README

### Changed

- Updated FISSURE Challenge details in README
- Updated current openings link in README

## 2025-1-18

Fixing Raspberry Pi OS installation errors.

### Changed

- Adjusted how netron is called for Raspberry Pi OS. User must manually browse for model file.
- openDatabaseConnection() attempts 10 retries with 2 second intervals when trying to connect to the database.

### Fixed

- Renamed actionICE9_Bluetooth_Sniffer to actionICE9_Bluetooth_Scanner in Frontend.py for Raspberry Pi OS 
- Updated installation for netron for Raspberry Pi OS
- Updated installation for docker for Raspberry Pi OS in PostgreSQL Database and IQEngine
- Database connection error when launching FISSURE for the first time

## 2025-1-13

Plugin updates for Library tab.

### Added

- Lessons Menu, Help Menu demo items
- Widgets and functionality for plugin support files
- Library utilities and plugin editor functions for editing plugins

### Changed

- Conditioner flow graph View button now uses database filepath to open flow graphs in GNU Radio Companion
- Append to plugin now only accepts zip files instead of folders
- Plugin CSV files need database table headers in first row

### Fixed

- FISSURE icon in taskbar and Dashboard are now visible if splash screen loses focus
- Updating how async_ok_dialog() is called to prevent heartbeat timeouts
- Append to plugin no longer fails for zip files without a password

## 2024-12-22

Endianness tab, unsigned integers, IQ Data tab upgrades.

### Added

- Endianness tab in IQ Data to swap between little endian and big endian formats
- Support for unsigned integers in the IQ Data tab
- previewIQ_File() to Qt5.py for opening a plot dialog to display truncated data
- Archive data type changes the data type in IQ Data tab after Plot is clicked

### Changed

- Edited IQ preview functions to use common previewIQ_File() function
- Expanded skip limits for plotting large IQ files
- Updated IQ Data > Convert tab to support batch processing and normalization
- Inserted extra data types and cleaned up IQ Data > Resample function
- Cleaned up IQ Data > Strip function
- Cleaned up IQ Data > OOK signal generation function

## 2024-12-19

Partial plugin updates and bug fixes.

### Added

- Initial plugin code for Library and Sensor Nodes tabs (disabled while under development)
- pyzipper in installer
- Clear buttons for triggers

### Fixed

- Adding missing parameters variable in Backend.py:retrieveDatabaseCache()
- Better centering for the splash screen "Loading..." label
- Inserted missing dashboard references to many standalone flow graph menu items that prevented flow graphs from opening
- Renamed "tableWidget1_tsi_conditioner_input_frequencies" to "tableWidget_tsi_conditioner_input_detector" to fix TSI detectors not updating results and progress
- User can no longer start TSI Conditioner if isolation method is not selected
- Guess no longer removes highlight in sensor node configuration

## 2024-12-12

Demo Menu for future automated testing.

### Added

- Demo Menu and menu items for testing/demonstrating Dashboard features 
- Slot functions for Demo Menu items
- Stop Demo Mode button behind FISSURE logo
- Asynchronous list widget, text edit dialog functions
- Standalone Menu and Tools Menu Demo Menu items

### Fixed

- Set backupCount to 1 in logging.yaml to prevent the event log from growing beyond maxBytes

## 2024-12-09

Networking and logging fixes.

### Added

- update_logging_levels() utility function
- INFO and DEBUG level logging for sending and receiving network messages
- List of banned command messages in FissureZMQNode.py for ignoring parameter values in logging

### Changed

- Moving temporary ipc files for local connections to /tmp folder
- Changed status bar "Shutdown" button to "Shut Down"
- Retrieve the Dashboard database cache on reconnect
- Disable more widgets on disconnect, enable them on database cache return
- Replaced updateLoggingLevel() callbacks with new utility function
- File logging now writes to a single .log file and the max size is reduced to 5 MB (logging.yaml)
- Removed temp.log file and writing to file when filtering log results

### Fixed

- Launch, disconnect, and launch networking fix for local sensor nodes
- Minimum logging levels in logger across software components set to match minimum level in console/file handlers
- Setting logging level in options dialog updates across all components
- Setting logging level in config files updates component logging levels on initialization

## 2024-12-02

Hardware ID requirement and splash screen fixes.

### Added

- Highlighting required hardware ID cells in Sensor Node Configuration scan results table

### Changed

- Hardware ID is now required when saving default hardware assignments

### Fixed

- Fixed isFloat() error when loading flow graph with Variable Fuzzing
- Optimizing splash screen code and image to avoid flicker

## 2024-12-01

Upgrading Conditioner tab to use radio hardware for Detector results and frequency list. Part 1.

### Added

- TSI Automation tab (empty)
- Detector results & frequencies input sources for TSI>Conditioner tab
- Function to add subdirectories to Python path in SensorNode.py
- Duplicated Conditioner flow graphs in preparation for hardware flow graphs

### Changed

- Moved detector flow graphs to Detectors folder
- Grouped conditioner flow graphs into File_Source and Hardware_Source folders
- Loading Conditioner categories, methods, and method parameters from the FISSURE library/database
- Modified conditioner_flow_graphs database table
- Removed old library backups YAML folder and files

### Fixed

- Changed detector results to sort time chronologically instead of lexicographically

## 2024-11-26

Z-Wave and ceiling fans lessons.

### Added

- Z-Wave lesson in menu and README
- Ceiling Fans lesson in menu and README

## 2024-11-25

Automatically launch database docker container, multi-stage import/export fixes

### Changed

- Moved certificate generator from cli.py to generate_certificates.py and updated installer
- Renamed _slotAttackMultiStageSaveClicked() to _slotAttackMultiStageExportClicked()
- Renamed _slotAttackMultiStageLoadClicked() to _slotAttackMultiStageImportClicked()
- Changed multi-stage attack export file to a YAML dictionary for export and import functions

### Fixed

- Launch database docker container on HIPRFISR startup if it is not running
- Adjusted frequency ranges for bladeRF 2.0 in IQ Record and IQ Playback tabs
- Multi-Stage export and import with triggers

## 2024-11-08

Fixing Library>Add tab.

### Fixed

- Library>Add combobox displaying the proper options and pages
- Adding /.env to .gitignore

## 2024-11-07

PostgreSQL database introduction to replace YAML libraries.

### Added

- Database files: example.env, docker-compose.yaml, db folder, fissure_db_dump.sql
- Splash screen while database caches are retrieved and Dashboard widgets finish updating
- pgAdmin link in Tools>Development menu
- Preview button for downloaded files in Archive tab
- Rename button for downloaded files in Archive tab
- RSPdx, RSPdx R2 options in Sensor Node Configuration dialog tabs (support only for GNU Radio 3.10 operating systems)
- More View File buttons in PD>Demodulation tab
- Link to FIRMS in Tools>Weather menu

### Changed

- Replaced library functions for retreiving, adding, and removing values from a YAML library to a database library
- Components can cache certain tables from the database located at the HIPRFISR for quick access (still stored in "backend.library" variable types)
- Removed Refresh button from Archive tab for the listview (listview updates automatically)
- Removed outdated Mode_S_PPM_dump1090.py file from maint-3.8 attacks
- Expanded TSI detector threshold ranges for spinboxes
- Widened OOK Signal Generator widgets, increased number of bursts spinbox range

### Fixed

- SDRPlay .grc file overwriting rtl2832U python file for the TSI wideband detector
- Expanded second installer GUI to prevent the buttons from overlapping the status text
- Selecting another file after deleting an item from Archive tab listview
- Ask for confirmation when deleting a file in IQ Data tab
- Filepath corrected for opening SigMF metadata file for SigMF button in IQ Data tab
- Removed .pyc files
- Refresh file list after doing IQ Data>Split action
- Dashboard no longer freezes when closing after Protocol Discovery is turned on without an active sensor node selected

## 2024-10-13

Import/Export installer software setups.

### Added

- Added Desmos graphing calculator to the Tools menu
- Added Needs Help button to the installer for listing unchecked (by default) tree items
- Added Import/Export buttons to the installer for recalling setups
- FISSURE Challenge image in README
- Local IQEngine support in README news
- Recall Installer Setups in README news
- 2024 FISSURE Challenge event in README

### Changed

- Added viridis colormap to IQ Data spectrogram to replace the black and white 
- Increase spectrogram NFFT from 1024 to 2048 

### Fixed

- Updated sed commands for gr-ais installer item in Kali and Ubuntu 24.04

## 2024-10-09

Fixing Kali installer errors and updating disk usage.

### Added

- Added installer option for Arch Linux (no support yet)

### Changed

- Disabling Bless, Arduino IDE, srsRAN, FoxtrotGPS for Kali in the installer and menu items
- Updated software disk usage in the installer for Kali

### Fixed

- Fixed error when starting second installer dialog for Kali
- Removed fromfile, complex64 imports from IQDataTabSlots.py which caused errors in Kali

## 2024-10-07

Updating Kali 2024.3 installer.

### Changed

- Replaced Kali references from 2023.1 to 2024.3 or removed version altogether

### Fixed

- Applying style sheets to the two installer Dialog objects to fix background color
- Fixed several Kali installer errors

## 2024-10-06

Updating Ubuntu 24.04 installer.

### Changed

- Updated disk usage for Ubuntu 24.04 software programs in instalelr

### Fixed

- Re-enabled Ubuntu 20.04 LTE programs and disabled Ubuntu 24.04 LTE program in installer
- Fixed rehex install on Ubuntu 20.04/24.04

## 2024-10-04

Fixing Ubuntu 24.04 install, removing beta designation.

### Changed

- Removed beta designation from Ubuntu 24.04 in installer GUI
- Updated installer image and OS table in README for Ubuntu 24.04

### Fixed

- Fixed several Ubuntu 24.04 installation errors for software tools

## 2024-10-04

Fixing some Ubuntu 24.04 installation errors.

### Fixed

- Installing Python2 for Ubuntu 24.04
- Adding --break-system-packages to pip commands for Ubuntu 24.04 (until a virtual environment is implemented)
- Updating some of the software sizes for Ubuntu 24.04 programs (will not be complete until the rest of the install is fixed)

## 2024-10-02

Writing disk usage to a file during installation.

### Added

- Modified installer to record software disk usage to `./Installer/disk_usage.txt`

## 2024-09-30

Fixing IQEngine install.

### Fixed

- Fixing directory for local IQEngine installation

## 2024-09-29

Local IQEngine, SOI Aggregator tab, and Ubuntu 24.04 (beta) support.

### Added

- IQEngine button to IQ Data tab functions
- Menu buttons for IQEngine: IQEngine - Online, IQEngine - Local, Stop Local Docker Container
- IQEngine installer item under Data category
- SOI Aggregator tab in TSI tab (no PD/library integration yet)
- Ubuntu 24.04 (beta) installer support

### Changed

- Moved updateCRC function to common.py

### Fixed

- Removed unused distro Python package from common.py

## 2024-09-25

3.10 OOK Generator block and GRCon24 video.

### Added

- ook_generator block to maint-3.10 gr-ainfosec
- General OOK Transmit attack for maint-3.10
- GRCon24 video link to the README

### Changed

- Grayed out GRCon24 event in README

## 2024-09-24

Support for RSPduo, RSPdx, and RSPdx R2: part 2 of 2.

### Added

- Flow graphs for RSPduo, RSPdx, and RSPdx R2
- Support for RSPdx and RSPdx R2 hardware (they require different GNU Radio source blocks)
- Link to "The Signal Path" under Lessons
- Added link to fieldspotter.radio in the menu
- Added link to plainsailing.ianrenton.com in the menu
- Added link to satellitemap.space in the menu
- Added link to HamSCI Resources under Lessons
- Added sphinx and sphinx_rtd_theme to the installer for building Read the Docs

### Changed

- Turned "Number of Files" table item into a spinbox in the IQ Data>Recording tab
- Removed example USRP and serial number saved in sensor node configuration file (default.yaml)
- Renamed example sensor node config files

### Fixed

- Removed errors when recording more than one file in the IQ Data tab
- Added more --break-system-packages to Raspberry Pi OS install

### Documentation

- Adding RSPdx, RSPdx R2 as supported hardware to README and user manual

## 2024-09-16

Support for RSPduo and RSPdx: part 1 of 2.

### Added

- Support for SDRplay RSPduo and RSPdx in Dashboard widgets (no flow graphs yet)
- gr-sdrplay3 OOT module to the installer for 3.10 operating systems (requires SDRplay API)
- DEF CON 32 RF Village prerecorded and live talk links to README
- GRCon24 link to README

### Fixed

- Exporting fissure Python module/directory to the PYTHONPATH as part of the fissure command in case the module is not recognized

### Documentation

- Added attack list to Operation section

## 2024-08-29

Fixing Add to Library button and multi-stage attack buttons.

### Added

- General sleep attack (Computer) for better control in playlists
- Other attack tree category

### Fixed

- Added Duration and Filename columns to Multi-Stage Up/Down buttons
- Fixed backend errors in Dashboard callbacks when Add to Library is clicked in Library tab
- Replaced synchronous error messages with asynchronous messages in LibraryTabSlots.py
- Parsing Attack tab Hardware combobox no longer breaks on hardware text without identifiers (Computer)
- Adding missing ook_generator GNU Radio block for maint-3.8/gr-ainfosec (still need to make maint-3.10 block) and General OOK Transmit attack flow graph

## 2024-08-22

Moving utility functions out of frontend code.

### Added

- Disable hardware probe button on click, enable on return

### Changed

- Moved checkFrequencyBounds(), hardwareDisplayName(), hardwareDisplayNameLookup() from Frontend.py to hardware.py
- Renamed ask_confirmation() to async_yes_no_dialog and moved from Frontend.py to Qt5.py
- Renamed ask_confirmation_ok() to async_ok_dialog and moved from Frontend.py to Qt5.py
- Moved errorMessage() from Frontend.py to Qt5.py
- Removed warningBox() from Frontend.py
- Moved isFloat() from Frontend.py to common.py, remove isFloat() from SensorNode.py

### Fixed

- Replaced synchronous error dialogs in asynchronous functions with asynchronous dialogs
- IQ Playback error now sets button text to "Play" instead of "Start"

### Documentation

- Added code examples for custom dialogs in Development section

## 2024-08-21

Networking and event loop fixes.

### Added

- LinkedIn link in README

### Changed

- Launch button sets local_remote field to local in sensor node code, field reserved for remembering configurations
- Replaced loopback address with IPC for HIPRFISR to sensor node connection
- Removed local_remote field description in README and RTD installation sections, no longer required to change to remote or local

### Fixed

- Updated sensor node probeHardware() to not block program
- Created separate heartbeat loops from event loops to prevent freezing
- Assigned sensor nodes a randomly generated UUID instead of a constant value for its message ID
- Added delays into event loops
- Improved right-click upon node deletion.
- Replaced print statements with logger messages in TargetSignalIdentification.py

## 2024-08-19

Updating Development section of user manual.

### Documentation

- Updating the Development section with details on how to modify the Dashboard for the new structural changes

## 2024-08-17

Removing DragonOS Focal installer.

### Changed

- Updated README to remove DragonOS Focal
- Removed DragonOS Focal from installer. Exits if detected.
- Adding deprecation warning to README in other branches

### Fixed

- Forcing setutools<71 for DragonOS FocalX install

## 2024-08-16

Updating installer for DragonOS FocalX.

### Fixed

- Removing unused installer categories for all operating systems
- Removing installer items already in DragonOS FocalX: qflipper, htop, qtdesigner
- Exporting FISSURE root folder as part of fissure command to avoid "missing fissure module" errors
- Adding FISSURE root folder to PYTHONPATH in SensorNode.py
- Forcing pyzmq>23.0.0 on DragonOS FocalX install to avoid zmq.SocketType errors
- Adding Network Certificates menu item in the installer for DragonOS FocalX
- Replacing c++11 with c++17 in gr-ais for DragonOS FocalX
- Adding depenencies for trackerjacker in DragonOS FocalX
- Checking gr-bluetooth item as default for DragonOS FocalX
- Adding opencv-python for DragonOS FocalX
- Installer now checks DragonOS FocalX instead of DragonOS Focal

## 2024-08-15

Updating installer for Parrot Security 6.1.

### Changed

- Updated installer photo in README to show Parrot OS 6.1

### Fixed

- Several Parrot Security 6.1 installer issues
- Table column resize for fuzzing variables with filepath button
- Changed the library filepaths for fuzzing blocks to point to new library locations
- Connected Mode S maint-3.8 fuzzing flow graph blocks
- Changed packetdiag command to packetdiag3 for Packet Diagram tool item in Parrot Security 6.1

## 2024-08-14

Updating Parrot OS 5.2 to Parrot Security 6.1.

### Added

- Link to FISSURE info sheet in README

### Changed

- Updating Parrot OS support from 5.2 to 6.1 (Security). Installer testing is incomplete.
- Grayed out DEF CON event

### Fixed

- Adding morse code special characters and error handling for unrecognized characters
- Installing opencv-python for motion detector trigger
- Selecting the appropriate combobox in Library>Browse tab for maint-3.8 or maint-3.10 library 

### Documentation

- Changing the release date from August 2021 to August 2022
- Adding info sheet link
- Updating license link to current default branch
- Removing duplicate labels for RTD sections

## 2024-08-07

Fixing autorun playlist stop and TSI Classifier issues.

### Fixed

- Set scikit-learn to version 1.3.2 in the installer to avoid errors
- Replaced np.float with np.float64 in TSITabSlots.py
- Inserted matplotlib.use('Qt5Agg') to get the confusion matrix to appear
- Archive Plot button now loads the file and plots it in IQ Data tab
- Autorun playlist now stops flow graphs completely for single-stage and multi-stage attacks

### Documentation

- Removed extra underscores from the Operation page

## 2024-08-07

Fixing installer and autorun playlist errors.

### Fixed

- Merged pull request #51 to add support for high resolution screens
- Autorun playlist item delay checkbox no longer produces an error
- Adding IPython to installer, also caused Network Certificates item to fail on install for older operating systems

### Documentation

- Updating information in Menu Items section regarding standalone flow graphs, tools, options, and view items

## 2024-08-03

Fixing Help menu items.

### Added

- Sensor Node and trigger user manual pages inserted into the menu

### Changed

- Removed outdated user manual pages from the help menu

### Fixed

- Help menu opens the pages in the local user manual
- Added missing CHANGELOG entry for 2024-08-01

### Documentation

- Miscellaneous spelling errors
- Adding missing Trigger file location
- Filled out Lessons section

## 2024-08-01

Remote sensor node updates.

### Added

- Sensor node configuration window for deploying remote or local sensor nodes
- Autorun playlists for scripting Single-Stage and Multi-Stage attack items to run with or without user interaction
- Trigger mechanisms and around 20 example scripts for single-stage attacks, multi-stage attacks, archive replay, and autorun playlists
- Sensor Node tab with Autorun Playlist and File Navigation tabs
- On-off keying signal generator
- Signal Classifier tab for training and testing machine learning models against extracted IQ data features
- More "General" protocol attack scripts
- More Mode S/ADS-B attack scripts
- Raw bit comparison between messages in PD Data Viewer tab

### Changed

- Moved the Packet Crafter tab under the Attack tab
- Replaced top buttons with Sensor Node buttons
- Replaced FGE code and moved flow graph functionality into SensorNode.py
- Refactored code base to separate callbacks, slots, classes, and use more asynchronous messaging
- Removed YAML definitions for messaging

### Fixed

- Library adding/removing errors

### Documentation

- Updated installation instructions with sensor node information and new FISSURE branch information
- Added "Remote Sensor Node Usage" section
- Added "Supported Sensor Node Hardware" section
- Added "Sensor Nodes" section
- Added "Sensor Nodes Tab" section
- Added "Triggers" section
- Added "Creating Triggers" section

## 2024-01-09

Binwalk and satellite links.

### Added

- Binwalk to the installer and menu
- N2YO, Find Satellites, AGSatTrack, Celestrak, Spot The Station to the menu
- Hideo Okawara's Mixed Signal Lecture Series (Tom Verbeure) to the Lessons Menu

### Fixed

- Adjusted gqrx install to source for Python3_maint-3.10 branch

## 2024-01-02

Updating FISSURE Challenge section in README

### Changed

- Moved and edited FISSURE Challenge section in README

## 2023-12-22

First attempt at Raspberry Pi OS (bookworm) install

### Added

- Raspberry Pi OS (bookworm) installer item, in beta status

### Fixed

- Changed hackrf_sweep check during install from `--help` to `-h`

## 2023-12-18

2023 FISSURE Challenge details

### Added

- FISSURE Challenge link to menu

### Changed

- 2023 FISSURE Challenge text in README

## 2023-12-11

2023 FISSURE Challenge announcement

### Added

- 2023 FISSURE Challenge announcement to README

### Fixed

- Multi-stage attacks with GUIs use Attack hardware defaults instead of IQ hardware defaults
- Adding missing python3-pyaudio to nrsc5 install

## 2023-12-08

Fixing flow graph with GUI attacks
 
### Added

- General Protocol and an IF flow graph for testing GUIs
- MLAT Feeder Map to menu

### Fixed

- Single-Stage and Multi-Stage Attacks load/run flow graphs with GUIs more like Inspection Flow Graphs using parameter blocks instead of variable blocks

## 2023-11-27

Signal Classifier widgets
 
### Added

- GPSJAM to the menu
- HF Propagation Map to the menu
- HAMRS to installer and menu
- GUI widgets for TSI Signal Classifier (no code yet)

## 2023-11-14

Split IQ tab
 
### Added

- Split IQ tab for making smaller files from one large file

### Fixed

- Added interrupt handlers to prevent programs hanging

## 2023-11-12

Menu links and installer updates
 
### Added

- OpenRailwayMap to the menu
- Orbital Element Converter to the menu
- Satellite Link Budget calculator to the menu
- WebSDR to the menu
- cemaxecuter YouTube to the menu
- Iceman YouTube to the menu
- Ubuntu 22.04.1, 22.04.2, 22.04.3 installer options

### Changed

- Combining HackRF, gr-osmosdr, and RTL installer checkboxes
- Enabling source gr-osmosdr during install for Python3_maint-3.8 branch

### Fixed

- Positioning HackRF install before gr-osmosdr
- Added fixed Documentation icon image sizes to the README to prevent poor resizing in certain browsers
- Updating Scapy file with tostring()/tobytes() error as part of Scapy install for Python3_maint-3.10 branch

## 2023-09-02

Feature Extractor and Python package updates
 
### Added

- Initial Feature Extractor GUI elements, code, and test files that generate example statistical features for Signal Classifier machine learning model training and testing

### Fixed

- Added missing yellowbrick and seaborn Python packages to installer for Python3_maint-3.10 branch and Python2_maint-3.7 branch (yellowbrick not working with Python2 branch)
- Removed extra commented code relating to Signal Conditioner
- Software and Conflicts link in the README points to Read the Docs (renamed to "Known Conflicts and Third-Party Software")
- Corrected formatting errors for Installation and About pages in user manual 

## 2023-08-28

Logo, README, Signal Conditioner updates
 
### Added

- Initial Signal Conditioner code for isolating signals from large streams of IQ data (files only for now)
- Logo image files

### Changed

- Updated FISSURE logo in Dashboard, README, and user manual
- Reordered README sections and modified some text

### Fixed

- Disabled SimpleScreenRecorder menu item from Python3_maint-3.10 branch (Wayland problems)
- No longer installing SimpleScreenRecorder by default in installer.py for Python3_maint-3.10 branch (Wayland problems)

## 2023-08-11

Copying Help menu items to Read the Docs, HD Radio fuzzing attack, Run with sudo option
 
### Added

- Read the Docs HTML files for offline viewing
- Renamed Help menu items to match Read the Docs headers
- Additional Help menu items to point to Read the Docs sections
- Link to towers.stratux.me in the menu
- Link to GNU Radio Hardware wiki page in the menu
- Link to APRS Track Direct in the menu 
- Documentation icons in the README
- Changed Usage text in README
- HD Radio fuzzing attack
- List of strings extracted from Naughty Strings to "Attack Files" folder
- "Run with sudo" checkbox in Single-Stage Attacks tab
- Multi-stage attacks check for "run\_with\_sudo" variable

### Changed

- Removed Tab Help GUI and menu item, replacing with Read the Docs
- Moved existing Help menu items to their corresponding Read the Docs headers
- Opening Help menu items to Read the Docs and no longer opening the markdown/html files
- Removed Documentation links from README
- Removed duplicate credits links in README
- Checking for run_with_sudo variable in attacks to set default value for "Run with sudo" checkbox
- Modifying the default values for certain filepath variables in attacks to reflect the location of FISSURE directory

### Fixed

- Python attack scripts no longer adding extra set of quotations to filepath variables
- Any attack variable with "filepath" in its name will be treated specially in flow graphs and Python scripts to ensure spaces are carried over correctly
- Attacks have the option to be run with sudo, sudo was an issue when calling flow graphs from a secondary Python script

## 2023-07-17

Automatic identification system (AIS) tools
 
### Added

- AIVDM/AIVDO Decoding, AIS VDM/VDO Decoder, AIS Online Decoder, pyais GitHub menu items
- Bit and Nibble counters in Data Viewer
- gla-rad/ais (gr-aistx) to Python3_maint-3.8 branch
- AiS_TX.grc standalone flow graph for Python_maint-3.8 branch
- ais_rx standalone flow graphs for Python3 branches

### Changed

- Replaced bistromath/gr-ais with bmagistro/gr-ais for Python3_maint-3.8 branch
- Removed ais_rx from Tools menu (open the Standalone flow graph instead) for Python3 branches
- README language for installing FISSURE

### Fixed

- gr-ais for Python3_maint-3.8 branch

## 2023-07-09

Installer, style, and Kali fixes.
 
### Added

- Check for Kali upon starting Dashboard
- Swapping gnome-terminal commands for qterminal in Kali
- Disabling Kali menu items that fail to install

### Changed

- Disabled radiosonde auto_rx for DragonOS FocalX install

### Fixed

- trackerjacker install
- ice9-bluetooth-sniffer, rehex install for Kali
- ComboBox font color of selected item set properly for Python3 branches
- Dynamic checkboxes set to follow stylesheets

## 2023-07-03

Miscellaneous style updates.
 
### Added

- Custom pushbutton/combobox text color option
- Disabled text color option
- Icon style (light/dark) color option
- Autofill combobox to populate custom color values (light/dark/custom)
- New color defaults to Options dialog

### Changed

- Assigned global combobox styles and removed extra lines for the exceptions
- Selection font and background colors
- Resized data type combobox in IQ Recording table

### Fixed

- Table comboboxes not resizing to the full height
- Table font size styling
- Combobox font color not set to a defined color
- Disabled doublespinbox/spinbox background color
- Removed extra padding in comboboxes
- Restored right align for certain comboxes
- Menu item shortcuts added to top level items
- Missing custom color replacements in the installer
- Added default values in CRC Calculator tab for Python3_maint-3.10 and Python2_maint-3.7 branches
- Constructed Sequence position in Packet Crafter tab for Python2_maint-3.7 branch

## 2023-06-28

Terminals for menu items, Read the Docs test files.
 
### Added

- Documentation section added to README
- Read the Docs test files for Python3_maint-3.10 branch
- Added FISSURE logo to all FISSURE .ui icons

### Changed

- Opening more menu items in terminal with expect script rather than launching them directly
- Removed beta designation in the installer and README from DragonOS FocalX
- Disabling LTE menu items requiring specific srsRAN configurations and locations for DragonOS FocalX

### Fixed

- Changed directory in command for \_slotMenuRdsRx2Clicked() for Python3_maint-3.8 branch

## 2023-06-25

Additional color options.
 
### Added

- Gpick to menu for DragonOS FocalX, disabled wl-color-picker
- Color options for buttons, comboboxes, disabled widgets, and hovered widgets
  
### Changed

- Disabling menu items on Dashboard launch based on operating system

### Fixed

- Set styles for disabled menu items
- Adjusting some single and double quotes to be consistent
- Removing trailing whitespace from main components

## 2023-06-23

DragonOS Focal/FocalX fixes.
 
### Added

- Checks for DragonOS in dashboard.py, fg_executor.py
- Replaced gnome-terminal commands with qterminal for DragonOS
- Added @menu_hover_padding to stylesheets to remove menubar item hover padding for DragonOS
  
### Changed

- ais_rx menu item opens a terminal with an example command instead of executing immediately
- Updated the Online Archive picture in README
- Removed ICE9 Bluetooth Sniffer from DragonOS FocalX install and changed the filepath for running the command

### Fixed

- Fixed wrong branch warning message during the install
- Removed extra line in \_slotMenuQtDesignerOptionsUiClicked()
- Updated DragonOS installer with fix for the expect_script (used to populate a terminal with text)
- Path locations for ais_rx, rds_rx, Iridium Extractor, Iridium Parser, and IridiumLive commands in Python3_maint-3.10 branch
- Executing btclassify.py with Python2
- Removed directory for kal example in the menu for DragonOS
- Replaced evince commands with open command for DragonOS
- Added extra '/' to qFlipper command for DragonOS to prevent extra text in terminal
- Moved default directories for srsRAN commands for DragonOS
- Changed where FalconGUI is called for DragonOS
- Changed where SDRTrunk is called for DragonOS
- Changed Python2 scapy2 version to 2.4.5 to avoid import errors with version 2.5.0

## 2023-06-19

Updating Archive collection functionality.
 
### Added

- Download of IQ collections and files from the FISSURE online archive in the Archive tab
- Filter Archive files by file extension
- Archive Collapse All, New Folder, Folder buttons
  
### Changed

- Updated library.yaml with Archive collection information
- Renamed "Folder" button to "Choose" in Archive tab
- Replaced Archive ListWidget with ListView
- Replaced Archive Collection TableWidget with TableView

### Fixed

- Minor styling changes
- Added missing <tr> to README

## 2023-06-12

Initial X410 support, gr-osmosdr fix, crop exclude, moving files into docs folder.
 
### Added

- Initial USRP X410 support (not tested yet, need examples)
- Exclude checkbox in Crop tab for removing the samples within a range
- Suggested .gitignore file extensions
  
### Changed

- Moved Gallery, Help, Icons, and Lessons folders to docs folder
- Applying style sheets for Python3_maint-3.8 and Python2_maint-3.7 installer dialogs

### Fixed

- Corrected the check for no IP address in TSI Detector tabs
- Minor GUI styling inconsistencies
- Replaced gr-osmosdr with a fork for Python3_maint-3.8 branch to fix osmocom and RTL GNU Radio blocks
- Inserting port value checks

## 2023-05-28

Append tab upgrade, qFlipper, renamed Clip tab, more Archive Dataset Builder buttons.
 
### Added

- Flipper Zero qFlipper in menu and installer for Python3 branches
- Regenerate button for Archive Dataset Builder table to update checkbox values
- Copy button for Archive Dataset Builder to avoid importing the same files over and over
  
### Changed

- Renamed clip tab to strip (to align with Python strip command)
- Clear "x" button for clip tab list widget
- Import multiple files for Append tab
- Remove multiple files for Archive Dataset Builder table

### Fixed

- Error handling for plotting unloaded IQ files in Plot All and Morse Code buttons
- Clip/Strip tab not changing color when changing style sheets

## 2023-05-14

Compile flow graphs option and Clip tab.
 
### Added

- Installer option to compile FISSURE flow graphs with grcc
- IQ Clip button to remove samples from an IQ file before and after a signal
  
### Changed

- Moved gr-ainfosec from Out-of-Tree Modules to Minimum Install category

### Fixed

- Styles for line widgets and list widgets
- Right align for certain comboboxes in Python3 branches

## 2023-05-01

Updating style sheets.
 
### Added

- GHex to the installer and menu
- ComboBox dark icon
- Ubuntu font installation to the install script
  
### Changed

- README with a sentence describing the minimal install items
- Setting font to Ubuntu for style sheets
- Removing default text for QTextEdits in .ui files/Qt Designer so style sheet font takes effect, setting values in init()
- Style sheets to match Python3_maint-3.10 branch style sheets

### Fixed

- Typo in Install UI and README image
- Adding transparent background to light-down-arrow icons for Python3_maint-3.10 branch
- Inserted missing custom color options in Options dialog for Python2_maint-3.7 and Python3_maint-3.8 branches
- IQ viewer button errors for Python2_maint-3.7 branch
- Changed blank sample rate value for FFT to a float from an int

## 2023-04-24

Adding support for Parrot OS and BackBox.
 
### Added

- Parrot OS, BackBox to installer as beta
- Kali software sizes
- Adding fonts-ubuntu to Kali install
  
### Changed

- README install icons and tables
- Unchecking RTLSDR-Airband in Kali install

### Fixed

- Installing VLC with apt-get for Kali

## 2023-04-17

Installer fixes and GUI style changes.
 
### Added

- Matplotlib toolbar icons
  
### Changed

- Manually setting icons for matplotlib toolbar to avoid color inversion
- Changing where the installer checks for DragonOS FocalX version (/etc/os-dragonos)

### Fixed

- Adding missing packages for Kali install: eog, Python2 cryptography, Python2 setuptools, xxd
- Removed freeglut3 for Kali install
- Downloading Anki from source for Kali
- Font color set to black for current program label in the installer
- Background color for inspection flow graph frame in Python3_maint-3.10 branch
- Removed wl-color-picker from DragonOS FocalX install and added Gpick
- Changing QTextEdit borders to avoid undesired scrollbars
- QComboBox padding-left adjusted in style sheets

## 2023-04-08

GUI styling fixes for Python3_maint-3.10 branch.
 
### Added

- Kali 23.1 install option for Python3_maint-3.10 branch (still in beta, needs additional adjustments)
- Random color scheme in menu
- Icons for light color scheme
  
### Changed

- Clicking Sample Rate and Frequency column header in dataset builder table applies first row value to all rows
- Kali 23.1 added to the README

### Fixed

- Frequency shift is no longer disabled in Archive dataset builder table for non-archive IQ files in Python3_maint-3.10 branch
- Applying stylesheets to Installer GUIs
- Inserting some of the missing elements in light mode style sheet
- Improved error handling for empty dataset builder values when start is clicked
- Clicking cancel on Custom Mode color picker keeps previous value instead of #000000
- get_xdata() error handling in dashboard.py to support more matplotlib versions

## 2023-04-03

Updating software sizes and fixing Python3_maint-3.10 installation.
 
### Added

- Solve Crypto with Force/scwf.dima.ninja to Tools Menu
- CrackStation.net to Tools Menu
  
### Changed

- Updated Python3_maint-3.10 software sizes for the installer

### Fixed

- Location of osmo-fl2k.git for fl2k install
- GNU Radio version that gets installed for Python3_maint-3.10 branch
- ESP32 BT Classic Sniffer install for Python3_maint-3.8 branch (Wireshark version is now 4.0.3)

## 2023-03-29

Updating software sizes and fixing Python3_maint-3.8 installation.
 
### Added

- 20.04.6 to the installer and README (same steps as 20.04.4)
  
### Changed

- Updated Python3_maint-3.8 software sizes for the installer
- Commented out gr-osmosdr from source in the installer for Python3_maint-3.8 branch and changed verify command

### Fixed

- ESP32 BT Classic Sniffer install for Python3_maint-3.8 branch (Wireshark version is now 4.0.3)
- radiosonde_auto_rx dependency python3-flask influenced pip through python3-openssl and is now commented out (fixes: sudo apt-get remove python3-openssl or delete /usr/lib/python3/dist-packages/OpenSSL)
- QSpectrumAnalyzer and Universal Radio Hacker install for Python3_maint-3.8 branch as a result of pip being corrupted by python3-flask/python3-openssl (see previous line)

## 2023-03-26

Preparing for Archive collections.
 
### Added

- File and Collection tabs for Archive Download
  
### Changed

- Updated Python2_maint-3.7 software sizes for the installer
- Moved noise source after scaling for dataset builder flow graph

### Fixed

- Added libuhd-dev to ICE9 Bluetooth Sniffer install

## 2023-03-19

Styling changes for Python2_maint-3.7 branch.
 
### Added

- Gpick to the Tools menu and installer for Python2_maint-3.7 and Python3_maint-3.8 branches
- wl-color-picker to the Tools menu and installer for Python3_maint-3.10 branch
- complextoreal.com to the Lessons menu
  
### Changed

- Small GUI style adjustments 

### Fixed

- Wideband detector plot background matches style when plotting points

## 2023-03-13

Styling changes for Python3_maint-3.10 branch.
 
### Added

- Light, Dark, and Custom modes for GUI styling for Python3_maint-3.10 branch

### Fixed

- Correcting PyQt widgets that were not updating colors for different styles for Python3_maint-3.8 branch
- Default widget styles updated to match light mode theme for Python3_maint-3.8 branch

## 2023-03-05

Styling changes for Python3_maint-3.8 branch.
 
### Added

- Light, Dark, and Custom modes for GUI styling for Python3_maint-3.8 branch
- View menu items for changing color modes for Python3_maint-3.8 branch
- light.css, dark.css, and custom.css files for Python3_maint-3.8 branch
- Color variables in options/default.yaml for Python3_maint-3.8 branch
- Truth column to Archive Dataset Builder table
- Dark Mode image to README
  
### Changed

- Removed stylesheets assigned to individual items in .ui files and inserted all styling into .css files for Python3_maint-3.8 branch.
- Stylesheet values for widgets in dashboard.py are pulled from options dialog for Python3_maint-3.8 branch
- Widget object names are used to apply stylesheets for Python3_maint-3.8 branch
- example.csv to match updated Dataset Builder table

### Fixed

- Several miscellaneous GUI adjustments for Python3_maint-3.8 branch
- Checking disabled columns in Dataset Builder table no longer toggles checkboxes

## 2023-02-25

Import/Export for Archive playlists, adding README images.
 
### Added

- Dataset Builder, Online Archive, Third-Party Tools images in README
- RF Reverse Engineering diagram in README
- Import/Export CSV buttons in Archive Replay tab
- Remove All button in Archive Replay tab
  
### Changed

- CRC Calculator image in README
- Name of archive.png to signal_playlists.png in README

### Fixed

- Removing an Archive playlist row keeps the selection at the current row
- Removing an Archive downloaded file keeps the selection at the current row

## 2023-02-24

Dataset builder in Archive tab.
 
### Added

- Dataset tab in Archive tab for altering IQ files in a reproducible way
- dataset_builder flow graph for creating altered IQ files

## 2023-02-22

Links to FISSURE Videos.
 
### Added

- YouTube link to FISSURE Videos in Help menu
- Video thumbnails and links in README
- Comment about git submodule command in README
  
### Changed

- idea_list.md content to reflect rejected GSoC status

## 2023-02-19

CRC RevEng and development tools.
 
### Added

- htop to installer and Tools menu
- OpenWebRX to installer and Tools menu for Python3 branches
- guidus, Systemback, Arduino, Geany, QtDesigner, grip, TuneIn Explorer, WSPR Rocks!, wttr.in to Tools menu
- Development and Weather categories to Tools menu
- CRC RevEng to installer
- CRC RevEng algorithms to Protocol Discovery (PD) CRC tab
- Empty Direction Finding tab
- CRC RevEng, htop, OpenWebRX to Credits, About, SoftwareAndConflicts
  
### Changed

- Moved Open-weather link to Weather category in Tools menu

## 2023-02-13

Installer categories and submodule checks.
 
### Added

- Expand All, Collapse All buttons in installer
- Label for the current program being installed
  
### Changed

- Installer now warns if git submodules have not been activated for out-of-tree modules
- Installer software list grouped by categories
- Split apart Video Tools and Audio Tools items in the installer
- Moved QSSTV to Ham Radio menu
- Updated contact instructions in idea list

### Fixed

- rtl_433 install for Python2_maint-3.7 branch

## 2023-02-06

Updating DragonOS FocalX install and adding idea list.
 
### Added

- 2023 Project Idea List
  
### Changed

- Installer image in README
- Links to AIS job opportunity sites

### Fixed

- Added missing escape characters in fissure command install
- Set DragonOS FocalX programs that do not install to be unchecked by default
- Commented out lines in the installer for software that is already installed in DragonOS FocalX 
- Regenerated "instantaneous_frequency_hackrf.py" to stop errors when running from Inspection Flow Graphs tab

## 2023-02-02

Adding DragonOS FocalX (beta) to installer, more links to Tools menu
 
### Added

- Link to IQEngine in the Tools menu
- Link to rfidpics in the Tools menu
- Link to acars.adsbexchange.com in the Tools menu
- Link to Airframes in the Tools menu
- DragonOS FocalX to the installer for Python3\_maint-3.10 branch
- Listed DragonOS FocalX with beta status in README
- Created checks for DragonOS FocalX in the install script for all branches
  
### Changed

- Renamed "Mode S" to "Aircraft" in the Tools menu

## 2023-01-29

New tools and reference material, moving Lessons, fixing installer.
 
### Added

- Meld to installer and Tools menu
- Dire Wolf example in the Tools menu
- hfpropagation.com in the Tools menu
- WaveDrom editor in the Tools menu
- nwdiag/packetdiag in the Installer and Tools menu for Python3 branches
- Git submodule instructions to Built With menu item
- HamClock to installer and Tools menu
- ICE9 Bluetooth Sniffer to installer and Tools Menu
- pocsagtx Standalone Flow Graph
- dump978 to installer and Tools menu
- TODO.md containing a list of potential ideas
  
### Changed

- Repositioned Ham Radio tools in the Tools menu
- Moved Lessons into HTML folder to preserve relative links to images
- Updated About.md, Credits.md, SoftwareAndConflicts.md with the latest tools

### Fixed

- Python3\_maint-3.8 installer fixes: gr-air-modes, pyFDA, SdrGlut, monitor\_rtl433
- Commented out paramiko from RouterSploit install in Python2_maint-3.7 branch
- Reverting rtl\_433 to release 22.11 to avoid installer errors in Python2\_maint-3.7 branch
- Adding libitpp-dev to gr-mixalot install

## 2023-01-25

Adding Dire Wolf, gr-mixalot, systemback, guidus
 
### Added

- Dire Wolf to the installer
- systemback and guidus to Python2 and Python3_maint-3.10 branches
- gr-mixalot submodule and installation for all branches
  
### Changed

- Moved Help HTML files to /Help/HTML to use the same relative path for images in Markdown and HTML files

### Fixed

- Help markdown files now show images when viewed on GitHub
- Python3\_maint-3.10 installer fixes: gr-paint, gr-air-modes, pyFDA, SdrGlut, monitor\_rtl433

## 2023-01-09

Fixing GNU Radio and gr-osmosdr installation.
 
### Added

- gr-osmosdr to HackRF install for Python3-maint_3.10 branch
  
### Changed

- Changed GNU Radio repository to ppa:gnuradio/gnuradio-releases for Python3-maint_3.10 branch
- Changed GNU Radio version to 3.10.5.0-0~gnuradio~jammy-1 for Python3-maint_3.10 branch
- Changed GNU Radio repository to ppa:gnuradio/gnuradio-releases-3.8 for Python3-maint_3.8 branch
- Changed GNU Radio repository to ppa:gnuradio/gnuradio-releases-3.7 for Python2-maint_3.7 branch
- Clarified "U.S." at the end of the README

### Fixed

- Osmocom blocks should work for HackRF flow graphs. Soapy HackRF block was producing a bad output.

## 2023-01-08

Creating bootable USBs, copying FM attacks, README updates
 
### Added

- Lesson12: Creating Bootable USBs
- "From Wav File" attacks for USRP B2x0, B20xmini, HackRF, bladeRF 2.0
- Logo to README
- "Inspection Flow Graphs" Help menu item
- Help Menu items in README
- Videos section in README
- "Interested In Working For AIS?" section in README
  
### Changed

- Added audio rate variable to "FM Radio - From Wav File" attacks
- Roadmap items in README
- Renamed "Uploading Flow Graphs" and "Uploading Python Scripts" to "Attack Flow Graphs" and "Attack Python Scripts"
- Updated "Attack Flow Graphs" and "Attack Python Scripts" Help Menu items
- Updated "Built With" Help Menu item with Python3 code
- Inserted QtDesigner image in "Modifying Dashboard" Help Menu item
- Inserted QtDesigner image in "Adding Custom Options" Help Menu item
- Moved Ubuntu 22.04 out of beta category in README
- Updated "Software and Conflicts" for 22.04 Kismet
 
### Fixed

- Kismet installation for Python3_maint-3.10 branch

## 2022-12-27

Additional support for USRP X300, B200, and B200mini.
 
### Added

- More support for X300, B200, B200mini
- Bootable USB software to the installer (systemback, guidus) for Python3_maint-3.8 branch
  
### Changed

- References to "USRP X310" to "USRP X3x0"
- References to "USRP B210" to "USRP B2x0"
- References to "USRP B205mini" to "USRP B20xmini"
 
### Fixed

- Hardware Guess button for USRP B200
- Hardware Guess button for USRP B200mini
- Fixed Detector Start button error on System stop for Python3_maint-3.10 branch

## 2022-12-21

Fixing IQ Playback tab.
 
### Fixed

- Playback tab no longer pulls the wrong values from the table cell widgets
- Removed CRC reverse lookup print statements
- Upgrading scipy during install to avoid import errors for Python3_maint-3.8 branch
- Adjusted USRP B210/B205mini, HackRF frequency limits

## 2022-12-19

Fixing CRC reverse lookup.
 
### Added

- Added link to cryptii.com in the menu
  
### Changed

- Adjusted gr-paint converter command to flip the image
 
### Fixed

- CRC reverse lookup now allows for lowercase hex characters
- Repositioned IQ viewer toolbar in Python2_maint-3.7 branch

## 2022-12-12

Adding RTLSDR Soapy blocks and hardware parameter limits.
 
### Added

- Gain and frequency spin boxes in IQ Record tab
- Sample rate combo box in IQ Record tab for RTL2832U
  
### Changed

- Python3_maint-3.10 RTL2832U flow graphs now use Soapy RTLSDR blocks and sample rates
- RTL2832U TSI wideband detector sample rate defaults
- RTL2832U "FM Radio - Audio Sink" attack adjusted for variable sample rate
 
### Fixed

- Addressed rgb/rgba warnings in dashboard.ui
- RTL2832U Inspection flow graphs had an incorrect sample rate option for 0.5 MS/s
- RTL2832U frequency ranges for Inspection flow graphs adjusted to 64-1700 MHz
- Replaced Standalone flow graphs with latest examples from gr-rds for Python3_maint-3.10 branch

## 2022-12-04

Program size estimates for install.
 
### Added

- The difference in hard drive space before and after the install is listed for programs. This was calculated from a single install with every box checked so pieces may be partially installed from previous checkboxes.
- Rankings button in the installer to display the top 30 largest programs and estimate the total size for a full install.
- 20.04.5 to the Python3_maint-3.8 installer. Performs the same install as 20.04.4 until differences are found.
   
### Changed

- README and images to show Ubuntu 20.04.5 and file size estimates for installer
 
### Fixed

- gr-bluetooth installation errors for Python3_maint-3.8 branch
- SdrGlut installation errors

## 2022-12-01

Updating IQ Data functions, adding filtering.
 
### Added

- Absolute Value, Differential, Keep 1 in 2 buttons, Unwrap, and Phase buttons in IQ Data tab
- Lowpass and bandpass filtering capabilities in IQ Data tab
- Clicking Start label sets the text edit value to 1 in IQ Data tab Plot frame
   
### Changed

- Removed IF2 button from IQ Data tab
- Resized and moved buttons in IQ Data tab
- Removed FFT sample rate from options dialog
- IQ Data functions/buttons apply to data in the window instead of reloading the IQ file, must plot again to reset
- Morse Code button is applied to data in the window
- Updated iq.png in README
 
### Fixed

- Archive download not storing IQ files correctly for filepaths containing spaces
- Instantaneous frequency calculation in IQ Data tab

## 2022-11-28

Correcting SigMF formatting issues.
 
### Added

- Comment with fix in SdrGlut install for potential libliquid.a errors in Python3_maint-3.10 branch
- Link to Amateur Satellite Database in Tools menu
   
### Changed

- Adjusted sigmf_test.sigmf-meta with "annotations" and "captures" corrections
 
### Fixed

- Adding empty "annotations" array/list to SigMF JSON
- Putting "captures" dictionary values into an array/list in the SigMF JSON

## 2022-11-27

SigMF recording and other functionality.
 
### Added

- Guess X310 daughterboards on multiple clicks within Hardware buttons
- Inspectrum button in IQ Data tab
- Morse Code Translator link in the Tools menu
- SigMF configuration for recording IQ files
- SigMF metadata file viewing
- SigMF frequency and sample rate parsing on IQ file load
- PSK Reporter link to Ham Radio Tools
   
### Changed

- Resized IQ Record table
 
### Fixed

- Updated error handling for opening an IQ file with Gqrx

## 2022-11-20

Adding Inspection file source flow graphs.
 
### Added

- IQ Inspection View buttons to open flow graphs in GNU Radio Companion
- IQ Inspection File flow graphs and controls to start/stop inspection flow graphs with file sources
- Link to triq.org in the menu
- pyFDA menu item to Python3 branches
   
### Changed

- Removed Rebuild checkbox in Inspection flow graphs
 
### Fixed

- gr-dect2 cmake installation error for Python3_maint-3.8

## 2022-11-16

Fixing GNU Radio 3.7.13.5 errors and adding new Detector tab.
 
### Added

- Integrated a modified GNU Radio tutorial example into a new Detector tab for Python2 and Python3_maint-3.8 branches
- Another image showcasing the installer to the README
- Created a block in gr-ainfosec to pass strings over ZMQ PUB without extra bytes
   
### Changed

- Removed unused TSI GUI elements and code in dashboard.py and tsi_component.py
- Adjusted variable default values in TSI flow graphs
 
### Fixed

- Set FE Corrections to True in UHD:USRP Source blocks for Python2 branch to suppress 3.7.13.5 errors
- Replaced correlate acces code blocks with newer versions in Python2 branch to work with 3.7.13.5
- Renamed TSI Sweep detector for USRP N2xx
- TSI detector plot points colormap scaled to 1 (instead of 255) to map properly for Python3 branches

## 2022-11-06

Adding tools to help with GRCon22 CTF challenges and changing how inspection flow graphs are called.
 
### Added

- QSSTV to install and menu
- m17-cxx-demod to install and menu for Python3 branches
- multimon-ng example command for POCSAG in Tools menu
- Fldigi to installer and menu
- Generic frequency translating standalone flow graph
   
### Changed

- Inspection flow graphs show GNU Radio parameter blocks
- Can edit values in inspection flow graph table
- GRCon22 video link in README
- Removed tools from IQ Data Inspection tab and added future space for running flow graphs on selected IQ files
 
### Fixed

- Inspection flow graphs loaded whatever was selected in the listbox instead of what was loaded in the table
- Inspection flow graphs can have channel, serial, and IP address values updated before runtime
- Added libpulse-dev to multimon-ng install

## 2022-10-30

Updating install to avoid potential errors.
 
### Added

- List widget, progress bar examples in Modifying Dashboard Help
- tpms_rx to the Tools menu of Python3_maint-3.10 branch
   
### Changed

- Updated About page with the latest credits
 
### Fixed

- Switched rtl-sdr.git address to https
- Updated install verification method for OOT modules to check for folders. Previously showed failures following the first instance of installing GNU Radio due to the Python paths not getting sourced in a running Python program.

## 2022-10-24

Adjusting install for RTL devices, adding links to lessons, and modifying README. Still need to replace RTL blocks with SoapySDR blocks in Python3_maint-3.10 branch flow graphs.
 
### Added

- Programming SDRs with GNU Radio link in Lessons
- Learn SDR link in Lessons
- Hack Chat Transcript link in README
   
### Changed

- Created links to FISSURE lessons in README
 
### Fixed

- Added gr-osmosdr install from source for Python3 branches so RTL-SDR blocks work for newer GNU Radio versions, but kept `sudo apt-get install -y gr-osmosdr` to avoid errors for now
- Added rtl-sdr install before gr-osmocom and rtl blacklist rules to get RTL devices working for the latest GNU Radio and gr-osmocom versions

## 2022-10-09

Updating GNU Radio and HackRF versions. Integrating a few more links, tools, and fixes.
 
### Added

- Software Defined Radio with HackRF in Lessons menu
- GNU Radio Tutorials in Lessons menu
- Sample rate and frequency edit boxes for IQ data
- Gqrx IQ data button for loading a file into Gqrx when sample rate and frequency is supplied
- SigDigger to installer, menu, CREDITS.md, SoftwareAndConflicts for Python3 branches (Python2 branch avoids PyQt5 programs)
- ham2mon for Python3 branches in installer, menu, CREDITS.md, SoftwareAndConflicts
- Links in README to GRCon22 slides, paper, video and AIS page
- HackRF to CREDITS.md and SoftwareAndConflicts
   
### Changed

- Moved PySDR menu item to Lessons menu
- Updated GNU Radio versions for each branch (3.7.11.0->3.7.13.5, 3.8.1.0->3.8.5.0, 3.10.1.1->3.10.4.0)
- Updated SoftwareAndConflicts help page with GNU Radio versions
- Removed old copy of HackRF release, downloading the latest as part of the install
- Edited Updating HackRF Firmware instructions in the help menu
 
### Fixed

- Launch Wireshark button in the Sniffer tab did not work for Python3 branches
- Added python-qwt5-qt4 to installer for enabling GNU Radio Filter Design Tool in Python2 branch
- Added RX1 antenna option for X3xx devices with TwinRX daughterboards to: TSI Wideband Detector settings, IQ Record settings
- Added pkg-config to HackRF install to fix cmake errors for Python2 branch
- Removed duplicate code in GNU Radio install for Python3_maint-3.8 branch

## 2022-09-25

Disabling IIO-Oscilloscope for Python2_maint-3.7 branch.
   
### Changed

- Disabled IIO-Oscilloscope for Python2_maint-3.7 due to its failure to install

## 2022-09-23

Adding support for bladeRF 2.0 micro and updating existing bladeRF content.
 
### Added

- bladeRF 2.0 micro support (Dashboard, Hardware Selection GUI, TSI Detector, Inspection flow graphs, IQ record/playback, Archive playback, adding attacks to library)
- adsb_parser block in gr-ainfosec for Python2_maint-3.7, Python3_maint-3.8 branches
- Added more bladeRF firmware support to the installer for: 40, A4, A9
- Guess button functionality for original bladeRF, serial number passed to flow graphs
- Added bladeRF 2.0 micro to hardware list in README
   
### Changed

- Moved gain variables for osmocom source/sink blocks to IF gain location for bladeRF flow graphs
- Installing bladeRF and gr-osmocom software from source for Python2_maint-3.7 branch to support bladeRF 2.0
- Resized bladeRF probe button window size
 
### Fixed

- Added missing ".py" for USRP N2xx TSI wideband detector name
- Resized hardware selection GUI for Python2_maint-3.7 branch
- Added missing hardware types in combobox for adding new demodulation flow graphs to library
- Changed bladeRF icon from a bladeRF 2.0 image

## 2022-09-18

USRP2 and USRP N2xx support was added but not tested against real devices. Please report any issues.
 
### Added

- USRP2, USRP N2xx support (Dashboard, Hardware Selection GUI, TSI Detector, Inspection flow graphs, IQ record/playback, Archive playback, adding attacks to library)
- Added more USRP daughterboards for hardware selection
   
### Changed

- Removed openHAB as a default option for DragonOS until further examination is completed
- Listed new hardware in the README
 
### Fixed

- Added a missing package in the DragonOS install for Viking

## 2022-09-13

The DragonOS Focal install has only a few more tools that need to be examined.
   
### Changed

- Updated installer for DragonOS Focal with more tools
- Formatted Credits.md
- Updated README with branch information
 
## 2022-09-10

Ubuntu 22.04 and the 3.10 OOT modules have been moved to a new branch: Python3_maint-3.10.
 
### Added

- Python3_maint-3.10 branch with 3.10 flow graphs, OOTs, and submodules
- Discord link to README
- Python3_maint-3.10 installer image to README
- Discord link to Help menu
   
### Changed

- Removed 3.10 OOT modules and submodules from Python3_maint-3.8 branch
- Python3_maint-3.8 installer image in README
- Branch information throughout the README
- Removed Ubuntu 22.04 from Python3_maint-3.8 installer
- Python2_maint-3.7 installer warnings and checks for other operating systems
- Disabled broken 22.04 tools in the Dashboard menu for Python3_maint-3.10 branch
 
### Fixed

- Removed attack history debug messages in Python3_maint-3.8 branch
- Check for KDE neon/Ubuntu 22.04 in the initial install script in Python3_maint-3.8 branch
- Updated commands for 802.11 Monitor Mode Tool for Ubuntu 22.04 in Python3_maint-3.10 branch
- Converted Monitor Mode Tool to Python3/PyQt5 for 3.8, 3.10 branches

## 2022-09-07

The new KDE neon install follows the same steps as Ubuntu 20.04.4. The GUIs look a little wonky due to the differences in Qt.

### Added

- Added KDE Neon (User - 5.25/20.04) option to the installer for the Python3 branch. Will be the same steps as 20.04.4 until a difference is found.

### Fixed

- Modified ESP32 Bluetooth Classic Sniffer installation to work with Wireshark 3.6.5.

## 2022-09-05

Ubuntu 22.04 is still not fully supported. The 3.10 flow graphs need to be integrated and tested. There are also a few issues remaining with the install.

### Changed

- Set installer checkbox defaults to False/unchecked for 22.04 tools that are known to not install properly
 
### Fixed

- "Verify" checks for 22.04 OOTs (Python3 imports)
- Clone command in README was not capitalized (changed fissure to FISSURE)
- PlutoSDR blocks with 'int' errors for Python2 branch
- Grip "Verify" check runs a different command

## 2022-09-04

Run these commands to download the Git submodules for the GNU Radio out-of-tree modules:
```
cd ./FISSURE
git submodule update --init
```
 
### Added

- Submodules to FISSURE repository for most of the out-of-tree modules
- Initial PlutoSDR support:
  - PlutoSDR installation with IIO Oscilloscope
  - ZWAVE PlutoSDR attack for testing
  - PlutoSDR Inspection flow graphs
  - PlutoSDR TSI Detector flow graph
  - PlutoSDR IQ Recording and Playback flow graphs
  - PlutoSDR Archive Playback flow graph
- IIO Oscilloscope and gr-iio to CREDITS.md, SoftwareAndConflicts.md
- IIO Oscilloscope to menu (SDR)
- Fork locations for OOTs to Credits.md
- 3.10 OOTs: gr-ainfosec, gr-fuzzer, gr-bluetooth, gr-limesdr, gr-tpms
   
### Changed

- Inserted command to download submodules (Out-of-Tree Modules) prior to installation in README.md
- Removed OOT modules to replace with submodules
- Made dashboard.py executable
- Moved install location for libbtbb (gr-bluetooth)
- Updated OOT folder names in the installer
 
### Fixed

- Python3 error when adding a new attack to the library
- A couple install issues and some of the missing items with the DragonOS install (not complete yet)
- OOT Versions in Ubuntu 22.04 SoftwareAndConflicts.md

## 2022-08-28

We are grateful to all developers whose software is installed and accessed with FISSURE.

### Added

- CREDITS.md
   
### Changed

- baudline install, removing local software copy
- Bless website in Software list
- Credits section to README
- Credits in About page

## 2022-08-27

DragonOS and Ubuntu 22.04 are still in beta status. They are under development and several features are known to be missing. Several items in the installer might conflict with existing programs or fail to install until the status is removed.
 
### Added

- maint-3.10 out-of-tree modules in Custom Blocks folder and the installer; still missing: gr-ainfosec, gr-fuzzer, gr-bluetooth, gr-limesdr(?)
- Ask to proceed before installing PyQt4/5 and other programs with the first installer program
- DragonOS Focal install option, software items are still being tested, check back later for a full verified list
   
### Changed

- SoftwareAndConflicts 22.04 OOT status
- README to expand on beta status for operating systems
 
### Fixed

- Updated Python2 branch to the latest gr-tpms_poore for better error handling
- Fixed 20.04 variable for Enscribe in 22.04 section of the installer

## 2022-08-25
 
### Added

- LTE-ciphercheck in installer, menu, software list, example ciphercheck.conf copied from Tools folder during install
- unihedron Electromagnetic Radiation Spectrum Poster v2 in menu
 
### Fixed

- Attack/Fuzzing Apply buttons were causing errors when adding entries to Attack History for the Python3 branch
- Link in README for Discussions and Issues pages
- Commented out `drb_config = drb.conf` in enb.conf for srsRAN in Python2 branch

## 2022-08-21

Impacts the Dashboard, Hardware Select UI, and flow graph library.
 
### Added

- Shortcut to Open-weather.community in the Tools Menu
- Serial number option for HackRFs in flow graphs (does not work with Inspection flow graphs) and Hardware Select UI, added Guess and Probe button functionality
   
### Changed

- Updated the Tab Help to better reflect all the tabs
- Serial number variable to HackRF flow graphs, requires `"hackrf=" + str(serial)` in source/sink blocks
- Hardware Selection UI width to show longer serial numbers and interface names
 
## 2022-08-15

Pull the latest *dashboard.py* to access future archive IQ files at a new address (https://fissure.ainfosec.com).
 
### Added

- CHANGELOG.md file
- Standalone flow graphs for generating J2497 signals with gr-j2497
- *Enscribe* to installer, menu, and Supported Software 
   
### Changed

- Archive file location moved to https://fissure.ainfosec.com
 
### Fixed

- Packet Crafter "Open" button was looking for a "Custom" protocol to populate. Now it only fills in the "Constructed Sequence" text edit box.

