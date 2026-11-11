"""RTL-SDR receive Action. 2.4MS/s -> 240k AIS IQ."""
from pathlib import Path
import logging
from typing import Callable, Optional
import importlib.util
import sys
root = Path(__file__).resolve().parent
if str(root) not in sys.path:
    sys.path.insert(0, str(root))
# FISSURE imports leaf Actions fresh, but may retain their shared parent in
# sys.modules after a plugin update. Load the parent from this installation.
shared_path = root / 'ais_osmosdr_receive.py'
spec = importlib.util.spec_from_file_location('fissure_ais_osmosdr_receiver_v090', str(shared_path))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
AISOsmoReceiver = shared.AISOsmoReceiver
from ais_device_lock_v081 import lock_radio as _lock_radio, unlock_radio as _unlock_radio


class OperationMain(AISOsmoReceiver):
    # Bind on the leaf class: cached older parent class may lack lock_radio.
    lock_radio = _lock_radio
    unlock_radio = _unlock_radio

    def __init__(self, duration_s=0, rf_frequency=162000000,
                 device_args='rtl=0', rx_gain=35, simulated_input=False,
                 emit_targets=True, detection_interval_s=5,
                 node_uid='', logger=logging.getLogger(__name__),
                 detection_callback: Optional[Callable] = None,
                 target_callback: Optional[Callable] = None,
                 status_callback: Optional[Callable] = None,
                 artifact_manager=None):
        # SensorNode.run_plugin_operation inspects this exact __init__ signature
        # and discards all callback/context keys not explicitly declared here.
        # **kwargs prevents live Detection and Target callbacks from arriving.
        super().__init__(radio_kind='rtl', duration_s=duration_s,
                         rf_frequency=rf_frequency, device_args=device_args,
                         rx_gain=rx_gain, simulated_input=simulated_input,
                         emit_targets=emit_targets,
                         detection_interval_s=detection_interval_s,
                         node_uid=node_uid, logger=logger,
                         detection_callback=detection_callback,
                         target_callback=target_callback,
                         status_callback=status_callback,
                         artifact_manager=artifact_manager)
