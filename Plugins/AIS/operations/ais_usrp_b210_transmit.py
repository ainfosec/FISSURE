"""Device-explicit FISSURE B210 TX Action. Uses the existing verified UHD workflow."""
from pathlib import Path
import sys
root = Path(__file__).resolve().parent
if str(root) not in sys.path:
    sys.path.insert(0, str(root))
import importlib.util
shared_path = root / 'ais_sdr_transmit.py'
spec = importlib.util.spec_from_file_location('fissure_ais_b210_transmitter_v091', str(shared_path))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
OperationMain = shared.OperationMain
