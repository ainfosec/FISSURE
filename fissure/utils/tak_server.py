#!/usr/bin/env python3
import asyncio
import xml.etree.ElementTree as ET
import pytak
from configparser import ConfigParser
import logging
import json


from fissure.utils.common import get_fissure_config
from fissure.callbacks import HiprFisrCallbacks

def load_config() -> ConfigParser:
    """
    Prepare TAK Configuration

    Returns
    -------
    ConfigParser
        Configuration parser object with TAK settings.
    """
    # load fissure config
    fissure_config = get_fissure_config()
    tak_config = fissure_config['tak']
    url = f"tls://{tak_config.get('ip_addr')}:{tak_config.get('port', '8089')}"

    # prepare config parser
    config = ConfigParser()
    config["mycottool"] = {"COT_URL": url}
    config = config["mycottool"]
    config["COT_URL"] = url
    config["PYTAK_TLS_CLIENT_CAFILE"] = tak_config.get('cert')
    config["PYTAK_TLS_CLIENT_CERT"] = tak_config.get('webadmin_cert')
    config["PYTAK_TLS_CLIENT_KEY"] = tak_config.get('key')
    config["PYTAK_TLS_DONT_VERIFY"] = str(1)
    config["PYTAK_TLS_CLIENT_PASSWORD"] = 'atakatak'
    return config

def gen_cot() -> str:
    """
    Generate CoT Event
    
    This is a simple example of generating a CoT Event.

    Returns
    -------
    str
        CoT Event as XML string.
    """
    root = ET.Element("event")
    root.set("version", "2.0")
    root.set("type", "a-f-G")  # insert your type of marker
    root.set("uid", "example")
    root.set("how", "h-g-i-g-o")
    root.set("time", pytak.cot_time())
    root.set("start", pytak.cot_time())
    root.set(
        "stale", pytak.cot_time(60)
    )  # time difference in seconds from 'start' when stale initiates
    detail = ET.SubElement(root, "detail")
    remarks = ET.SubElement(detail, "remarks")
    remarks.text = "Testing Testing2"
    contact = ET.SubElement(detail, "contact")
    callsign = ET.SubElement(contact, "callsign")
    callsign.text = "example"
    pt_attr = {
        "lat": "40.781789",  # set your lat (this loc points to Central Park NY)
        "lon": "-73.968698",  # set your long (this loc points to Central Park NY)
        "hae": "0",
        "ce": "0",
        "le": "0",
    }
    ET.SubElement(root, "point", attrib=pt_attr)
    print(ET.tostring(root))
    return ET.tostring(root)

class TakSender(pytak.QueueWorker):
    """
    TAK Sender Class
    """
    def __init__(self, queue: asyncio.queues.Queue, config: ConfigParser, cot: str, logger: logging.Logger = logging.getLogger()):
        """Initialize TAK Sender.

        Parameters
        ----------
        queue : asyncio.queues.Queue
            The queue to send data to.
        config : ConfigParser
            Configuration parser object with TAK settings.
        cot : str
            CoT Event as XML string.
        logger : logging.Logger, optional
            Logger instance, by default logging.getLogger()
        """
        super().__init__(queue, config)
        self._logger = logger
        self.cot = cot

    async def run(self):
        await self.put_queue(self.cot)

class TakReceiver(pytak.QueueWorker):
    """
    TAK Receiver Class

    Overload handle_data to process received CoT Events.
    """
    def __init__(self, queue: asyncio.queues.Queue, config: ConfigParser, hipfisr: object = None, logger: logging.Logger = logging.getLogger()):
        """Initialize TAK Receiver.

        Parameters
        ----------
        queue : asyncio.queues.Queue
            The queue to receive data from.
        config : ConfigParser
            Configuration parser object with TAK settings.
        hipfisr : object, optional
            HIPRFISR instance, by default None
        logger : logging.Logger, optional
            Logger instance, by default logging.getLogger()
        """
        super().__init__(queue, config)
        self._logger = logger
        self.hipfisr = hipfisr




    async def handle_data(self, data: bytes) -> None:
        """
        Handle data from the receive queue.

        Expects WinTAK->FISSURE requests in:
        <event ... uid="{request_uid}" type="t-x-fissure">
            <detail>
                <fissure>
                    <request>plugin_action</request>
                    <request_id>fissure-req-...</request_id>
                    <node_uid>...</node_uid>
                    <requester_uid>...</requester_uid>              (optional)
                    <requester_callsign>...</requester_callsign>    (optional)
                    <plugin_name>...</plugin_name>
                    <action_name>...</action_name>
                    <parameters_json>{...}</parameters_json>        (optional; JSON object)
                </fissure>
            </detail>
        </event>
        """
        try:
            data_decode = data.decode("utf-8", errors="replace")
        except Exception:
            data_decode = str(data)

        self._logger.info("TAK Msg Received:\n%s\n", data_decode)

        try:
            root = ET.fromstring(data_decode)
            
            # Event metadata
            event_uid = root.get("uid", "unknown")
            event_type = root.get("type", "unknown")

            detail = root.find(".//detail")
            if detail is None:
                return

            fissure = detail.find("fissure")
            if fissure is None:
                return

            request = (fissure.findtext("request") or "").strip().lower()
            if not request:
                return

            # Correlation ID
            request_id = (fissure.findtext("request_id") or "").strip() or event_uid

            # Required target node
            node_uid = (fissure.findtext("node_uid") or "").strip()

            # Optional requester identity
            requester_uid = (fissure.findtext("requester_uid") or "").strip()
            requester_callsign = (fissure.findtext("requester_callsign") or "").strip()

            # print("request_id: ", request_id)
            # print("node_uid: ", node_uid)
            # print("requester_uid: ", requester_uid)
            # print("requester_callsign: ", requester_callsign)
            # request_id:  fissure-req-0ed55a49-3038-4861-825d-c6a9785d5c0a
            # node_uid:  fe241d26-c5e0-44d0-8bdd-48f7106fc4e2
            # requester_uid:  a54d8311-fe41-5c16-8dc3-8e4457ba176c
            # requester_callsign:  ANDY985


            # Targets list
            if request in ("targets_list", "target_list", "get_targets", "get_target_list"):  # targets_list
                await HiprFisrCallbacks.sendTargetsListTak(
                    self.hipfisr,
                    requester_uid=requester_uid,
                    requester_type="tak",
                    request_id=request_id,
                    requester_callsign=requester_callsign,
                )
                return

            if not node_uid:
                self._logger.warning(
                    "FISSURE request missing node_uid (request=%s, request_id=%s, event_uid=%s, event_type=%s, requester_uid=%s)",
                    request, request_id, event_uid, event_type, requester_uid or "none"
                )
                return

            plugin_name = (fissure.findtext("plugin_name") or "").strip()
            action_name = (fissure.findtext("action_name") or "").strip()

            # -----------------------------
            # parameters_json (ONLY)
            # -----------------------------
            parameters = {}

            params_json = fissure.findtext("parameters_json")
            if params_json:
                try:
                    parsed = json.loads(params_json)
                    if not isinstance(parsed, dict):
                        raise ValueError("parameters_json must decode to a JSON object")
                    parameters = parsed
                except Exception as e:
                    self._logger.warning(
                        "Invalid parameters_json (node_uid=%s, request_id=%s): %s",
                        node_uid, request_id, str(e)
                    )
                    return

            self._logger.info(
                "FISSURE RX request=%s node_uid=%s request_id=%s event_uid=%s requester_uid=%s callsign=%s parameters=%s",
                request,
                node_uid,
                request_id,
                event_uid,
                requester_uid or "none",
                requester_callsign or "none",
                list(parameters.keys()) if parameters else "none",
            )

            # -----------------------------
            # Dispatch
            # -----------------------------
            # Query
            if request in ("plugin_names", "plugins", "get_plugin_names", "ecosystem_plugin_names"):  # plugin_names, ecosystem_plugin_names
                if request == "ecosystem_plugin_names":
                    tak_context = "ecosystem"
                else:
                    tak_context = "node"
                await HiprFisrCallbacks.sendPluginNamesTak(
                    self.hipfisr,
                    requester_uid,
                    "tak",
                    node_uid,
                    tak_context
                )

            # Load Plugin
            elif request in ("plugin_actions", "get_plugin_actions", "ecosystem_plugin_actions"):  # plugin_actions, ecosystem_plugin_actions
                if not plugin_name:
                    self._logger.warning(
                        "plugin_actions requested but plugin_name missing (node_uid=%s, request_id=%s)",
                        node_uid, request_id
                    )
                    return
                
                if request == "ecosystem_plugin_actions":
                    tak_context = "ecosystem"
                else:
                    tak_context = "node"

                await HiprFisrCallbacks.sendPluginActionNamesTak(
                    self.hipfisr,
                    requester_uid,
                    "tak",
                    plugin_name,
                    node_uid,
                    tak_context
                )

            # Customize Action
            elif request in ("customize_action", "ecosystem_customize_action"):
                if not plugin_name or not action_name:
                    self._logger.warning(
                        "plugin_action missing plugin_name/action_name (node_uid=%s, request_id=%s, plugin=%s, action=%s)",
                        node_uid,
                        request_id,
                        plugin_name or "missing",
                        action_name or "missing"
                    )
                    return
                
                if request == "ecosystem_customize_action":
                    tak_context = "ecosystem"
                else:
                    tak_context = "node"

                await HiprFisrCallbacks.sendPluginActionParametersTak(
                    self.hipfisr,
                    requester_uid,
                    "tak",
                    node_uid,
                    plugin_name=plugin_name,
                    action_name=action_name,
                    tak_context=tak_context
                )                

            # Execute Action
            elif request in ("plugin_action", "execute_plugin_action", "run_plugin_action"):
                if not plugin_name or not action_name:
                    self._logger.warning(
                        "plugin_action missing plugin_name/action_name (node_uid=%s, request_id=%s, plugin=%s, action=%s)",
                        node_uid,
                        request_id,
                        plugin_name or "missing",
                        action_name or "missing"
                    )
                    return

                await HiprFisrCallbacks.sendPluginActionTak(
                    self.hipfisr,
                    requester_uid,
                    "tak",
                    [node_uid],
                    plugin_name=plugin_name,
                    action_name=action_name,
                    parameters=parameters,
                )

            # Execute Ecosystem Action
            elif request == "ecosystem_execute_action":
                if not plugin_name or not action_name:
                    self._logger.warning(
                        "ecosystem_execute_action missing "
                        "plugin_name/action_name "
                        "(node_uid=%s, request_id=%s, "
                        "plugin=%s, action=%s)",
                        node_uid,
                        request_id,
                        plugin_name or "missing",
                        action_name or "missing",
                    )
                    return

                node_uids_json = (
                    fissure.findtext("node_uids_json") or ""
                ).strip()

                if not node_uids_json:
                    self._logger.warning(
                        "ecosystem_execute_action missing "
                        "node_uids_json "
                        "(node_uid=%s, request_id=%s)",
                        node_uid,
                        request_id,
                    )
                    return

                try:
                    selected_node_uids = json.loads(
                        node_uids_json
                    )
                except Exception as exc:
                    self._logger.warning(
                        "ecosystem_execute_action invalid "
                        "node_uids_json "
                        "(node_uid=%s, request_id=%s, "
                        "error=%s)",
                        node_uid,
                        request_id,
                        exc,
                    )
                    return

                if (
                    not isinstance(selected_node_uids, list)
                    or len(selected_node_uids) == 0
                ):
                    self._logger.warning(
                        "ecosystem_execute_action "
                        "node_uids_json was not a "
                        "non-empty list "
                        "(node_uid=%s, request_id=%s)",
                        node_uid,
                        request_id,
                    )
                    return

                selected_node_uids = [
                    str(uid).strip()
                    for uid in selected_node_uids
                    if str(uid).strip()
                ]

                if not selected_node_uids:
                    self._logger.warning(
                        "ecosystem_execute_action had no "
                        "valid node UIDs "
                        "(node_uid=%s, request_id=%s)",
                        node_uid,
                        request_id,
                    )
                    return

                await HiprFisrCallbacks.sendPluginActionTak(
                    self.hipfisr,
                    requester_uid,
                    "tak",
                    selected_node_uids,
                    plugin_name=plugin_name,
                    action_name=action_name,
                    parameters=parameters,
                )

            # Stop Action
            elif request in ("plugin_action_stop", "stop_plugin_action", "stop_all"):
                await HiprFisrCallbacks.stop_all_plugin_operations(
                    self.hipfisr,
                    requester_uid,
                    "tak",
                    [node_uid],
                )
            
            # Stop Ecosystem Actions
            elif request == "ecosystem_stop_action":
                node_uids_json = (
                    fissure.findtext("node_uids_json") or ""
                ).strip()

                if not node_uids_json:
                    self._logger.warning(
                        "ecosystem_stop_action missing node_uids_json "
                        "(node_uid=%s, request_id=%s)",
                        node_uid,
                        request_id,
                    )
                    return

                try:
                    selected_node_uids = json.loads(node_uids_json)
                except Exception as exc:
                    self._logger.warning(
                        "ecosystem_stop_action invalid node_uids_json "
                        "(node_uid=%s, request_id=%s, error=%s)",
                        node_uid,
                        request_id,
                        exc,
                    )
                    return

                if (
                    not isinstance(selected_node_uids, list)
                    or len(selected_node_uids) == 0
                ):
                    self._logger.warning(
                        "ecosystem_stop_action node_uids_json was not a "
                        "non-empty list (node_uid=%s, request_id=%s)",
                        node_uid,
                        request_id,
                    )
                    return

                selected_node_uids = [
                    str(uid).strip()
                    for uid in selected_node_uids
                    if str(uid).strip()
                ]

                if not selected_node_uids:
                    self._logger.warning(
                        "ecosystem_stop_action had no valid node UIDs "
                        "(node_uid=%s, request_id=%s)",
                        node_uid,
                        request_id,
                    )
                    return

                await HiprFisrCallbacks.stop_all_plugin_operations(
                    self.hipfisr,
                    requester_uid,
                    "tak",
                    selected_node_uids,
                )
                        
            # Artifact Download
            elif request in ("artifact_download", "get_artifact", "download_artifact"):
                artifact_id = parameters.get("artifact_id")

                if not artifact_id:
                    self._logger.warning(
                        "artifact_download requested but artifact_id missing (node_uid=%s, request_id=%s)",
                        node_uid, request_id
                    )
                    return

                self._logger.info(
                    "Artifact download requested (artifact_id=%s, node_uid=%s, request_id=%s)",
                    artifact_id, node_uid, request_id
                )

                # Match the original behavior: request transfer to TAK, with no inline data
                await HiprFisrCallbacks.transferArtifactRequest(self.hipfisr, artifact_id, "tak")

            # SOIs list
            elif request in ("sois_list", "soi_list", "get_sois", "get_soi_list"):
                await HiprFisrCallbacks.sendSoisListTak(
                    self.hipfisr,
                    requester_uid=requester_uid,
                    requester_type="tak",
                    node_uid=node_uid,
                    request_id=request_id,
                    requester_callsign=requester_callsign,
                )
                return
            
            # Artifacts list
            elif request in ("artifacts_list"):
                await HiprFisrCallbacks.sendArtifactsListTak(
                    self.hipfisr,
                    requester_uid=requester_uid,
                    requester_type="tak",
                    node_uid=node_uid,
                    request_id=request_id,
                    requester_callsign=requester_callsign,
                )
                return
            
            # Complete SOI evidence Mission Package
            elif request in (
                "soi_evidence_download",
                "download_soi_evidence",
            ):
                soi_id = str(
                    parameters.get("soi_id")
                    or ""
                ).strip()

                if not soi_id:
                    self._logger.warning(
                        "soi_evidence_download missing soi_id "
                        "(node_uid=%s, request_id=%s)",
                        node_uid,
                        request_id,
                    )
                    return

                try:
                    await (
                        HiprFisrCallbacks
                        .sendSoiEvidencePackageTak(
                            self.hipfisr,
                            soi_id=soi_id,
                            requester_uid=requester_uid,
                        )
                    )
                except Exception:
                    self._logger.exception(
                        "SOI evidence package failed "
                        "(soi_id=%s, request_id=%s)",
                        soi_id,
                        request_id,
                    )

                return

            # Complete Target data Mission Package
            elif request in (
                "target_data_download",
                "download_target_data",
            ):
                target_id = str(
                    parameters.get("target_id")
                    or ""
                ).strip()

                if not target_id:
                    self._logger.warning(
                        "target_data_download missing target_id "
                        "(node_uid=%s, request_id=%s)",
                        node_uid,
                        request_id,
                    )
                    return

                try:
                    await (
                        HiprFisrCallbacks
                        .sendTargetDataPackageTak(
                            self.hipfisr,
                            target_id=target_id,
                            requester_uid=requester_uid,
                        )
                    )
                except Exception:
                    self._logger.exception(
                        "Target data package failed "
                        "(target_id=%s, request_id=%s)",
                        target_id,
                        request_id,
                    )

                return

            
            # Promote existing detection directly to authoritative SOI
            elif request == "promote_detection_to_soi":
                detection = parameters.get("detection")

                if not isinstance(detection, dict) or not detection:
                    self._logger.warning(
                        "promote_detection_to_soi missing detection object "
                        "(node_uid=%s, request_id=%s)",
                        node_uid,
                        request_id,
                    )
                    return

                detection.setdefault("node_uid", node_uid)

                await HiprFisrCallbacks.promoteDetectionToSoi(
                    self.hipfisr,
                    detection=detection,
                    requester_uid=requester_uid,
                    requester_callsign=requester_callsign,
                )
                return

            # Promote existing detection directly to authoritative target
            elif request == "promote_detection_to_target":
                detection = parameters.get("detection")

                if not isinstance(detection, dict) or not detection:
                    self._logger.warning(
                        "promote_detection_to_target missing detection object "
                        "(node_uid=%s, request_id=%s)",
                        node_uid,
                        request_id,
                    )
                    return

                detection.setdefault("node_uid", node_uid)

                await HiprFisrCallbacks.promoteDetectionToTarget(
                    self.hipfisr,
                    detection=detection,
                    requester_uid=requester_uid,
                    requester_callsign=requester_callsign,
                )
                return

            # Promote existing authoritative SOI directly to authoritative target
            elif request == "promote_soi_to_target":
                soi = parameters.get("soi")

                if not isinstance(soi, dict) or not soi:
                    self._logger.warning(
                        "promote_soi_to_target missing soi object "
                        "(node_uid=%s, request_id=%s)",
                        node_uid,
                        request_id,
                    )
                    return

                soi.setdefault("node_uid", node_uid)

                soi_id = str(
                    soi.get("soi_id")
                    or ""
                ).strip()

                if not soi_id:
                    self._logger.warning(
                        "promote_soi_to_target missing soi_id "
                        "(node_uid=%s, request_id=%s)",
                        node_uid,
                        request_id,
                    )
                    return

                target_id = f"soi-{soi_id}"

                frequency_mhz = None
                frequency_value = soi.get("frequency_mhz")

                if frequency_value not in (None, "", "None"):
                    try:
                        frequency_mhz = float(frequency_value)
                    except (TypeError, ValueError):
                        self._logger.warning(
                            "promote_soi_to_target invalid frequency_mhz=%r "
                            "(node_uid=%s, soi_id=%s)",
                            frequency_value,
                            node_uid,
                            soi_id,
                        )

                model_classification = str(
                    soi.get("model_classification")
                    or ""
                ).strip()

                database_classification = str(
                    soi.get("database_classification")
                    or ""
                ).strip()

                display_label = (
                    model_classification
                    or database_classification
                    or "SOI"
                )

                model_confidence = soi.get(
                    "model_confidence"
                )

                def _optional_float(value):
                    if value in (None, "", "None"):
                        return None

                    try:
                        return float(value)
                    except (TypeError, ValueError):
                        return None

                lat = _optional_float(
                    soi.get("latitude")
                    if "latitude" in soi
                    else soi.get("lat")
                )

                lon = _optional_float(
                    soi.get("longitude")
                    if "longitude" in soi
                    else soi.get("lon")
                )

                hae_m = _optional_float(
                    soi.get("hae_meters")
                    if "hae_meters" in soi
                    else soi.get("hae_m")
                )

                classification_candidates = []

                if model_classification:
                    classification_candidates.append({
                        "source": "model",
                        "label": model_classification,
                        "confidence": model_confidence,
                    })

                if database_classification:
                    classification_candidates.append({
                        "source": "database",
                        "label": database_classification,
                        "confidence": "",
                    })

                patch = {
                    "target_id": target_id,
                    "node_uid": str(
                        soi.get("node_uid")
                        or node_uid
                        or ""
                    ).strip(),
                    "source_soi_id": soi_id,
                    "frequency_mhz": frequency_mhz,
                    "classification": {
                        "display_label": display_label,
                        "candidates": classification_candidates,
                    },
                    "location": {
                        "lat": lat,
                        "lon": lon,
                        "hae_m": hae_m,
                        "ce_m": 100,
                        "source": "soi",
                    },
                    "state": "observed",
                    "artifact_id": "",
                    "artifact_ids": [],
                    "artifact_links": [],
                }

                history_entry = {
                    "event": "soi_promoted_to_target",
                    "soi_id": soi_id,
                    "operation_id": str(
                        soi.get("operation_id")
                        or ""
                    ).strip(),
                    "requester_uid": requester_uid,
                    "requester_callsign": requester_callsign,
                }

                await HiprFisrCallbacks.targetPatch(
                    self.hipfisr,
                    target_id=target_id,
                    patch=patch,
                    history_entry=history_entry,
                    artifact_id="",
                )

                self._logger.info(
                    "Promoted WinTAK SOI to target "
                    "(soi_id=%s, target_id=%s, node_uid=%s)",
                    soi_id,
                    target_id,
                    node_uid,
                )
                return            
            
            # Refresh Status
            elif request in ("refresh_status"):
                await HiprFisrCallbacks.refresh_status(
                    self.hipfisr,
                    requester_uid,
                    "tak",
                    [node_uid]
                )
            
            # Query Target Actions
            elif request in ("query_target_actions"):
                if not plugin_name:
                    self._logger.warning(
                        "query_target_actions requested but plugin_name missing (node_uid=%s, request_id=%s)",
                        node_uid, request_id
                    )
                    return

                await HiprFisrCallbacks.sendPluginTargetActionsTak(
                    self.hipfisr,
                    requester_uid,
                    "tak",
                    plugin_name,
                    node_uid,
                    target_id=parameters.get("target_id"),
                )

            # Geolocate Start
            elif request in ("geolocate_target_start"):
                await HiprFisrCallbacks.geolocate_target_start(
                    self.hipfisr,
                    requester_uid,
                    "tak",
                    parameters=parameters,
                )

            # Geolocate Stop
            elif request in ("geolocate_target_stop"):
                await HiprFisrCallbacks.geolocate_target_stop(
                    self.hipfisr,
                    requester_uid,
                    "tak",
                    parameters=parameters,
                )
                     
            else:
                self._logger.debug(
                    "Ignoring unknown request '%s' (node_uid=%s, request_id=%s)",
                    request, node_uid, request_id
                )

        except ET.ParseError as e:
            self._logger.error("XML Parse Error: %s", e)
        except Exception as e:
            self._logger.exception("handle_data failed: %s", e)


    async def run(self) -> None:
        """
        Wait forever for CoT events from TAK server.
        Only exits on shutdown or None sentinel.
        """
        self._logger.debug("TAK Receiver started, waiting for data...")

        while True:
            try:
                data = await self.queue.get()  # blocks until a message arrives

                # pytak uses None as shutdown sentinel in some cases
                if data is None:
                    self._logger.debug("TAK receiver got shutdown signal.")
                    return

                await self.handle_data(data)

            except asyncio.CancelledError:
                # Task cancelled cleanly on shutdown
                return
            except Exception as e:
                self._logger.error(f"TAK receiver error: {e}")
                await asyncio.sleep(1)

async def main(rx: bool = True, tx: bool = False):
    """
    TAK server client main function

    Parameters
    ----------
    rx : bool, optional
        Enable receiving, by default True
    tx : bool, optional
        Enable transmitting, by default False
    """
    # load config
    config = load_config()

    # Initializes worker queues and tasks.
    clitool = pytak.CLITool(config)
    await clitool.setup()

    logger = logging.getLogger("TakReceiver")
    logger.setLevel(logging.INFO)
    while True:
        # add tasks
        tasks = []
        if rx:
            tasks.append(TakReceiver(clitool.rx_queue, config, logger=logger))
        if tx:
            tasks.append(TakSender(clitool.tx_queue, config, cot=gen_cot(), logger=logger))
        clitool.add_tasks(
            set(tasks)
        )

        # run task
        await clitool.run()

        # wait before restarting
        await asyncio.sleep(1.0)

if __name__ == "__main__":
    asyncio.run(main(True, True))