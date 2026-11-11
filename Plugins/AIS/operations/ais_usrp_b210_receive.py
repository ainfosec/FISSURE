"""Device-explicit FISSURE B210 RX Action. Uses the existing verified UHD workflow."""
from pathlib import Path
import importlib.util
import sys
root = Path(__file__).resolve().parent
if str(root) not in sys.path:
    sys.path.insert(0, str(root))
# Do not reuse an older shared B210 receiver cached by the Sensor Node.
shared_path = root / 'ais_sdr_receive.py'
spec = importlib.util.spec_from_file_location('fissure_ais_b210_receiver_v097', str(shared_path))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
OperationMain = shared.OperationMain
