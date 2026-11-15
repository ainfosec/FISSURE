"""Dashboard-only reconciliation of manual Action panels after node disconnection.

Sensor Nodes own execution. A missing Action after reconnect is NOT proof of
Completed, Stopped, or Failed; it only means no longer in the active registry.
"""

from fissure.Dashboard.Slots import SingleActionTabSlots, FuzzingTabSlots
from fissure.Dashboard.Slots.TSITabSlots import conditioner as ConditionerSlots
from fissure.Dashboard.Slots.TSITabSlots import feature_extractor as FeatureSlots
from fissure.Dashboard.Slots.TSITabSlots import capture as CaptureSlots
from fissure.Dashboard.Slots.TSITabSlots import detector as DetectorSlots
from fissure.Dashboard.Slots.TSITabSlots import survey as SurveySlots
from fissure.Dashboard.Slots.TSITabSlots import inspection as InspectionSlots
from fissure.Dashboard.Slots.TSITabSlots import classifier as ClassifierSlots
from fissure.Dashboard.Slots import SequentialActionTabSlots


# UI labels are informational; the node UID and operation ID remain the identity.
_PANELS = (
    ("single", "single_action_node_uid", "single_action_operation_id",
     ("single_action_start_pending", "single_action_running"),
     "label_ta_single_action_execution_status", "pushButton_ta_single_action_start_stop"),
    ("fuzzing", "fuzzing_node_uid", "fuzzing_operation_id",
     ("fuzzing_start_pending", "fuzzing_running"),
     "label_ta_fuzzing_execution_status", "pushButton_ta_fuzzing_start_stop"),
    ("conditioner", "tsi_conditioner_node_uid", "tsi_conditioner_opid",
     ("tsi_conditioner_running",),
     "label2_tsi_conditioner_run_status", "pushButton_tsi_conditioner_run_start_stop"),
    ("features", "tsi_fe_node_uid", "tsi_fe_operation_id",
     ("tsi_fe_running",),
     "label2_tsi_fe_run_status", "pushButton_tsi_fe_run_start_stop"),
    ("capture", "sa_capture_node_uid", "sa_capture_operation_id",
     ("sa_capture_running",),
     "label_sa_capture_execution_status", "pushButton_sa_capture_start_stop"),
    ("detector", "tsi_detector_node_uid", "tsi_detector_opid",
     ("tsi_detector_running",),
     "label2_tsi_detector_status", "pushButton_tsi_detector_start_stop"),
    ("survey", "sa_survey_node_uid", "sa_survey_operation_id",
     ("sa_survey_start_pending", "sa_survey_running"),
     "label_sa_survey_execution_status", "pushButton_sa_survey_execution_start_stop"),
    ("inspection", "sa_inspection_action_node_uid", "sa_inspection_action_operation_id",
     ("sa_inspection_action_running",),
     "label_sa_inspection_actions_status", "pushButton_sa_inspection_actions_start_stop"),
    ("classifier", "sa_classifier_model_node_uid", "sa_classifier_operation_id",
     ("sa_classifier_running",),
     "label2_sa_classifier_classify_run_status", "pushButton_sa_classifier_classify_run_start_stop"),
)


def _current(dashboard, spec):
    kind, node_attr, id_attr, active_attrs, _label, _button = spec
    uid = str(getattr(dashboard, node_attr, "") or "").strip()
    operation_id = str(getattr(dashboard, id_attr, "") or "").strip()
    active = any(bool(getattr(dashboard, name, False)) for name in active_attrs)
    if kind == "classifier":
        # A Library Match is local hub work, not a Sensor Node operation.
        active = bool(active and getattr(dashboard, "sa_classifier_model_launched", False)
                      and not getattr(dashboard, "sa_classifier_model_operation_complete", False))
    return uid, operation_id, active


def _set_panel_notice(dashboard, spec, message, enable_stop=False):
    _kind, _uid, _opid, _active, label_name, button_name = spec
    label = getattr(dashboard.ui, label_name, None)
    if label is not None:
        label.setText(message)
        label.setToolTip(
            "The Sensor Node disconnected. An operation's remote outcome cannot "
            "be inferred from connectivity alone."
        )
    button = getattr(dashboard.ui, button_name, None)
    if button is not None:
        button.setEnabled(bool(enable_stop))


def _halt_local_sequence(dashboard, uid):
    """Stop the Dashboard's future schedule, NOT an unverified remote Action."""
    if not bool(getattr(dashboard, "sequential_actions_running", False)):
        return
    if str(getattr(dashboard, "sequential_actions_node_uid", "") or "").strip() != uid:
        return
    if bool(getattr(dashboard, "sequential_actions_connection_lost", False)):
        return

    dashboard.sequential_actions_connection_lost = True
    dashboard.sequential_actions_stop_requested = True
    # Do not send new Stop commands to a disconnected node. The remote state
    # will be visible in Tactical after reconnection and snapshot reconciliation.
    dashboard.sequential_actions_detector_operation_ids = set()
    dashboard.sequential_actions_current_stop_reason = "connection_lost"
    dashboard.sequential_actions_current_result = "stopped"
    current_event = getattr(dashboard, "sequential_actions_current_event", None)
    if current_event is not None and not current_event.is_set():
        current_event.set()
    detection_event = getattr(dashboard, "sequential_actions_detection_event", None)
    if detection_event is not None and not detection_event.is_set():
        detection_event.set()

    SequentialActionTabSlots._append_sequence_log(
        dashboard,
        "Sensor Node disconnected: sequence scheduling halted locally. "
        "The remote Action may still be running; inspect Tactical after reconnect.",
    )
    dashboard.ui.label_ta_sequential_actions_execution_status.setText(
        "Connection Lost — Halting Sequence..."
    )
    dashboard.ui.pushButton_ta_sequential_actions_start_stop.setEnabled(False)


def mark_node_disconnected(dashboard, node_uid):
    """Freeze active panel stop controls without manufacturing terminal events."""
    uid = str(node_uid or "").strip()
    if not uid:
        return
    pending = getattr(dashboard, "_manual_action_recovery_pending", None)
    if pending is None:
        pending = dashboard._manual_action_recovery_pending = {}

    for spec in _PANELS:
        node, operation_id, active = _current(dashboard, spec)
        if node != uid or not operation_id or not active:
            continue
        kind = spec[0]
        _set_panel_notice(dashboard, spec, "Connection Lost — Action Unknown")
        # Detector gating is still locally orchestrated; cancel that scheduler
        # rather than treating its not-yet-started main operation as missing.
        if not (kind == "single" and bool(getattr(dashboard, "single_action_waiting_for_detection", False))):
            pending[kind] = (uid, operation_id)
        if kind == "conditioner":
            dashboard.tsi_conditioner_connection_suspended = True
        if kind == "single" and bool(getattr(dashboard, "single_action_waiting_for_detection", False)):
            # A detector-gated action is controlled by a local Dashboard task.
            # It must not launch the main Action later based on a stale Detection.
            dashboard.single_action_connection_lost = True
            dashboard.single_action_stop_requested = True
            dashboard.single_action_detector_operation_ids = set()
            event = getattr(dashboard, "single_action_detection_event", None)
            if event is not None and not event.is_set():
                event.set()

    # A Library Match may be pending before a model Action is submitted.
    # Do not launch that deferred model while its chosen Sensor Node is offline.
    if (bool(getattr(dashboard, "sa_classifier_running", False))
            and bool(getattr(dashboard, "sa_classifier_model_node_uid", ""))
            and str(getattr(dashboard, "sa_classifier_model_node_uid", "") or "").strip() == uid
            and not bool(getattr(dashboard, "sa_classifier_model_launched", False))):
        dashboard.sa_classifier_stop_requested = True
        dashboard.sa_classifier_library_pending = False
        dashboard.sa_classifier_model_pending = False
        ClassifierSlots._sa_classifier_set_running(
            dashboard, False, "Connection Lost — Model Not Started"
        )

    _halt_local_sequence(dashboard, uid)


def mark_node_reconnected(dashboard, node_uid):
    """Continue freezing affected controls until the correlated snapshot arrives."""
    uid = str(node_uid or "").strip()
    pending = getattr(dashboard, "_manual_action_recovery_pending", {}) or {}
    for spec in _PANELS:
        kind = spec[0]
        node, operation_id, active = _current(dashboard, spec)
        if active and node == uid and pending.get(kind) == (uid, operation_id):
            _set_panel_notice(dashboard, spec, "Reconnected — Verifying Action...")


async def _restore_running_panel(dashboard, kind, uid, operation_id):
    """Only re-enable Stop after an authoritative active operation was observed."""
    if kind == "single":
        dashboard.single_action_stop_requested = False
        await SingleActionTabSlots.handle_single_action_operation_state(
            dashboard, node_uid=uid, operation_id=operation_id, state="Running"
        )
        dashboard.ui.label_ta_single_action_execution_status.setText("Running (Reconnected)")
    elif kind == "fuzzing":
        dashboard.fuzzing_stop_requested = False
        await FuzzingTabSlots.handle_fuzzing_operation_state(
            dashboard, node_uid=uid, operation_id=operation_id, state="Running"
        )
        dashboard.ui.label_ta_fuzzing_execution_status.setText("Running (Reconnected)")
    elif kind == "conditioner":
        dashboard.tsi_conditioner_stop_requested = False
        dashboard.tsi_conditioner_connection_suspended = False
        ConditionerSlots._tsi_conditioner_set_run_button_state(dashboard, True)
        ConditionerSlots._tsi_conditioner_set_run_status(dashboard, "Running (Reconnected)")
    elif kind == "features":
        dashboard.tsi_fe_stop_requested = False
        FeatureSlots.update_tsi_fe_run_start_state(dashboard)
        dashboard.ui.label2_tsi_fe_run_status.setText("Running (Reconnected)")
    elif kind == "capture":
        dashboard.sa_capture_stop_pending = False
        dashboard.ui.pushButton_sa_capture_start_stop.setEnabled(True)
        dashboard.ui.label_sa_capture_execution_status.setText("Capturing (Reconnected)")
    elif kind == "detector":
        dashboard.tsi_detector_stop_pending = False
        dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(True)
        DetectorSlots._tsi_detector_set_status_text(dashboard, "Running (Reconnected)")
    elif kind == "survey":
        dashboard.sa_survey_start_pending = False
        dashboard.sa_survey_running = True
        dashboard.sa_survey_stop_requested = False
        SurveySlots._set_sa_survey_execution_locked(dashboard, True)
        SurveySlots._set_sa_survey_start_stop_button(dashboard, True)
        dashboard.ui.pushButton_sa_survey_execution_start_stop.setEnabled(True)
        dashboard.ui.label_sa_survey_execution_status.setText("Running (Reconnected)")
    elif kind == "inspection":
        InspectionSlots._set_sa_inspection_action_running(dashboard, uid, operation_id)
        dashboard.ui.label_sa_inspection_actions_status.setText("Running (Reconnected)")
    elif kind == "classifier":
        dashboard.sa_classifier_stop_requested = False
        ClassifierSlots._sa_classifier_set_running(dashboard, True, "Running (Reconnected)")
        # This reconciliation still owns the pending entry until it returns.
        dashboard.ui.pushButton_sa_classifier_classify_run_start_stop.setEnabled(True)


async def _resolve_missing_panel(dashboard, kind, uid, operation_id):
    """The Action is absent from the node's active registry: outcome unknown."""
    message = "Outcome Unknown — Not Active After Reconnect"
    if kind == "single":
        await SingleActionTabSlots._finish_single_action(
            dashboard, "Outcome Unknown", node_status="No longer in active Action snapshot"
        )
    elif kind == "fuzzing":
        await FuzzingTabSlots._finish_fuzzing(dashboard, "Outcome Unknown")
    elif kind == "conditioner":
        dashboard.tsi_conditioner_connection_suspended = False
        # A local metadata result, if present, is stronger evidence than the
        # absence of a still-active operation and should retain its results.
        payload = ConditionerSlots._tsi_conditioner_read_run_metadata(dashboard)
        if payload and str(payload.get("operation_id") or "").strip() == operation_id:
            ConditionerSlots._tsi_conditioner_set_run_finished_from_payload(dashboard, payload)
            return
        dashboard.tsi_conditioner_running = False
        dashboard.tsi_conditioner_stop_requested = False
        dashboard.tsi_conditioner_node_uid = ""
        dashboard.tsi_conditioner_waiting_for_opid = False
        ConditionerSlots._tsi_conditioner_set_run_button_state(dashboard, False)
        ConditionerSlots._tsi_conditioner_set_run_status(dashboard, message)
        ConditionerSlots._tsi_conditioner_update_workflow_ribbon(dashboard)
    elif kind == "features":
        FeatureSlots._tsi_fe_finish_local_run(dashboard, status=message, progress=0)
    elif kind == "capture":
        CaptureSlots._set_sa_capture_stopped(dashboard, message)
    elif kind == "detector":
        DetectorSlots._tsi_detector_cleanup_remote_xpra(dashboard)
        DetectorSlots._tsi_detector_set_stopped(dashboard)
        DetectorSlots._tsi_detector_set_status_text(dashboard, message)
    elif kind == "survey":
        SurveySlots._finish_sa_survey(dashboard, "Outcome Unknown")
    elif kind == "inspection":
        InspectionSlots._set_sa_inspection_action_stopped(dashboard, message)
    elif kind == "classifier":
        timer = getattr(dashboard, "sa_classifier_result_timer", None)
        if timer is not None:
            timer.stop()
        dashboard.sa_classifier_library_pending = False
        dashboard.sa_classifier_model_pending = False
        dashboard.sa_classifier_model_operation_complete = True
        ClassifierSlots._sa_classifier_set_running(dashboard, False, message)
    dashboard.logger.warning(
        "[Recovery] %s Action %s on %s is no longer active; outcome unverified.",
        kind, operation_id, uid,
    )


async def reconcile_from_activity_snapshot(dashboard, node_uid, operations, requested_at):
    """Reconcile only panels frozen by this node's disconnect event.

    Skip snapshots superseded by a newer per-operation lifecycle edge.
    Never reset a panel currently bound to a different operation ID.
    """
    uid = str(node_uid or "").strip()
    if not uid or not requested_at:
        return
    node = (getattr(dashboard, "node_states", {}) or {}).get(uid, {}) or {}
    if not isinstance(node, dict) or node.get("connected") is not True:
        return

    live_ids = {
        str(entry.get("operation_id") or "").strip()
        for entry in operations or []
        if isinstance(entry, dict) and str(entry.get("operation_id") or "").strip()
    }
    pending = getattr(dashboard, "_manual_action_recovery_pending", None)
    if not isinstance(pending, dict):
        return
    events = getattr(dashboard, "plugin_operation_last_event_times", {}) or {}
    mirror = (getattr(dashboard, "active_plugin_operations", {}) or {}).get(uid, {}) or {}

    for spec in _PANELS:
        kind = spec[0]
        entry = pending.get(kind)
        if not entry or entry[0] != uid:
            continue
        operation_id = entry[1]
        node, current_id, active = _current(dashboard, spec)
        if (node, current_id) != (uid, operation_id) or not active:
            pending.pop(kind, None)
            continue

        if events.get((uid, operation_id), 0) > requested_at:
            # A newer event wins. Terminal events will independently reset the
            # panel; a newer Running edge may restore it directly.
            record = mirror.get(operation_id, {})
            if isinstance(record, dict) and record.get("state") in {"Starting", "Running"}:
                await _restore_running_panel(dashboard, kind, uid, operation_id)
            pending.pop(kind, None)
            continue

        if operation_id in live_ids:
            await _restore_running_panel(dashboard, kind, uid, operation_id)
        else:
            await _resolve_missing_panel(dashboard, kind, uid, operation_id)
        pending.pop(kind, None)