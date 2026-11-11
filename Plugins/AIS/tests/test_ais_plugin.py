"""AIS plugin tests. Fake-pyais tests validate FISSURE integration, not RF.

Actual pyais codec roundtrip is tested separately when pyais is installed.
"""
import asyncio
import importlib.util
import json
import logging
from pathlib import Path
import socket
import sys
import types
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.ais_codec import AISMessageAssembler, checksum_valid, normalize_message, to_nmea_lines


def nmea(payload, number=1, total=1, seq="", channel="A"):
    body = "!AIVDM,%d,%d,%s,%s,%s,0" % (total, number, seq, channel, payload)
    crc = 0
    for character in body[1:]:
        crc ^= ord(character)
    return "%s*%02X" % (body, crc)


def test_nmea_checksum_and_tag_block():
    msg = nmea("1:200000001:37.000:-122.000")
    assert checksum_valid(msg)
    assert to_nmea_lines("\\s:test*33\\" + msg + "\n") == [msg]
    assert not checksum_valid(msg[:-2] + "00")
    assert not checksum_valid("!AIVDM,1,1,,A,foo,0")
    assert to_nmea_lines("noise\n" + msg) == [msg]


def test_normalize_no_false_geolocation():
    no_position = normalize_message({"type": 5, "mmsi": 200000001, "shipname": "TEST"}, [nmea("x")])
    assert no_position["reported_position_valid"] is False
    assert "latitude" not in no_position
    assert no_position["mmsi"] == "200000001"
    assert normalize_message({"type": 1, "mmsi": 200000001, "lat": 91, "lon": 181}, [nmea("x")])["reported_position_valid"] is False
    assert normalize_message({"type": 1, "mmsi": 200000001, "lat": 37, "lon": -122}, [nmea("x")])["reported_position_valid"] is True


class FakeMessage:
    def __init__(self, fields):
        self.fields = fields

    def asdict(self):
        return self.fields


def fake_encode_dict(row, radio_channel="A", talker_id="AIVDM"):
    mmsi = str(row["mmsi"])
    if row["type"] == 5:
        payload = "5:%s:%s" % (mmsi, row["shipname"].replace(" ", "_"))
        return [nmea(payload[:12], total=2, number=1, seq="7", channel=radio_channel),
                nmea(payload[12:], total=2, number=2, seq="7", channel=radio_channel)]
    payload = "1:%s:%s:%s" % (mmsi, row["lat"], row["lon"])
    return [nmea(payload, channel=radio_channel)]


def fake_decode(*frames):
    encoded = "".join(frame.split("*")[0].split(",")[5] for frame in frames)
    fields = encoded.split(":")
    if fields[0] == "5":
        return FakeMessage({"type": 5, "mmsi": int(fields[1]), "shipname": fields[2].replace("_", " ")})
    return FakeMessage({"type": 1, "mmsi": int(fields[1]), "lat": float(fields[2]),
                        "lon": float(fields[3]), "speed": 6.0, "course": 35.0})


@pytest.fixture
def fake_pyais(monkeypatch):
    main = types.ModuleType("pyais")
    main.decode = fake_decode
    main.__version__ = "test-double"
    encode = types.ModuleType("pyais.encode")
    encode.encode_dict = fake_encode_dict
    monkeypatch.setitem(sys.modules, "pyais", main)
    monkeypatch.setitem(sys.modules, "pyais.encode", encode)


def test_fragment_assembly(fake_pyais):
    parts = fake_encode_dict({"type": 5, "mmsi": 200000001, "shipname": "DEMO"})
    parser = AISMessageAssembler()
    assert parser.push(parts[0]) is None
    result = parser.push(parts[1])
    assert result["ship_name"] == "DEMO"
    assert result["mmsi"] == "200000001"
    assert result["reported_position_valid"] is False
    assert parser.invalid_count == 0


class FakeArtifactManager:
    def __init__(self, root):
        self.root = root
        self.artifacts = []

    def create_operation_dir(self, opid):
        folder = self.root / opid
        folder.mkdir(parents=True, exist_ok=True)
        return None, str(folder)


class FakeOperation:
    def __init__(self, node_uid="", logger=None, detection_callback=None, target_callback=None,
                 status_callback=None, artifact_manager=None, **kwargs):
        self.node_uid = node_uid
        self.logger = logger or logging.getLogger("ais-test")
        self.detection_callback = detection_callback
        self.target_callback = target_callback
        self.status_callback = status_callback
        self.artifact_manager = artifact_manager
        self.opid = str(uuid.uuid4())
        self._stop = False

    def create_artifact(self, files, name, artifact_type, metadata, relations=None, file_metadata=None):
        assert all(Path(path).is_file() for path in files)
        self.artifact_manager.artifacts.append((files, name, artifact_type, metadata))
        if not hasattr(self.artifact_manager, "relations"):
            self.artifact_manager.relations = {}
        artifact_id = "artifact-test-%d" % len(self.artifact_manager.artifacts)
        self.artifact_manager.relations[artifact_id] = relations
        if not hasattr(self.artifact_manager, "file_metadata"):
            self.artifact_manager.file_metadata = {}
        self.artifact_manager.file_metadata[artifact_id] = file_metadata
        return artifact_id

    def update_artifact(self, artifact_id, metadata=None, relations=None):
        index = int(str(artifact_id).split("-")[-1]) - 1
        if index < 0 or index >= len(self.artifact_manager.artifacts):
            return False
        files, name, kind, previous = self.artifact_manager.artifacts[index]
        previous.update(metadata or {})
        self.artifact_manager.artifacts[index] = (files, name, kind, previous)
        if relations is not None:
            self.artifact_manager.relations[artifact_id] = relations
        return True

    async def _sleep_stop_aware(self, sec, check_interval_s=0.1):
        await asyncio.sleep(sec)
        return not self._stop


def import_operations(monkeypatch):
    # Operations are loaded by the Sensor Node from file paths.
    modules = {name: types.ModuleType(name) for name in (
        "fissure", "fissure.utils", "fissure.utils.plugins", "fissure.utils.plugins.operations")}
    modules["fissure.utils.plugins.operations"].Operation = FakeOperation
    for name, obj in modules.items():
        monkeypatch.setitem(sys.modules, name, obj)

    def import_file(name):
        spec = importlib.util.spec_from_file_location(name, ROOT / "operations" / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    return import_file("ais_receive"), import_file("ais_simulate")


def test_udp_simulation_end_to_end(fake_pyais, monkeypatch, tmp_path):
    receiving, simulating = import_operations(monkeypatch)
    manager = FakeArtifactManager(tmp_path)
    detections, targets, statuses = [], [], []

    async def detection(row):
        detections.append(row)

    async def target(**row):
        targets.append(row)

    async def status(message):
        statuses.append(message)

    async def scenario():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ephemeral:
            ephemeral.bind(("127.0.0.1", 0))
            port = ephemeral.getsockname()[1]
        receiver = receiving.OperationMain(input_mode="udp", listen_port=port, duration_s=0.65,
                                           detection_callback=detection, target_callback=target,
                                           status_callback=status, artifact_manager=manager,
                                           node_uid="local-test")
        sender = simulating.OperationMain(vessel_count=2, position_updates=2, interval_s=0.1,
                                          udp_port=port, status_callback=status,
                                          artifact_manager=manager, node_uid="local-test")
        recv_task = asyncio.create_task(receiver.run())
        await asyncio.sleep(0.05)
        await sender.run()
        await recv_task
        return receiver, sender

    receiver, sender = asyncio.run(scenario())
    assert sender.sentences == 8  # two 2-part static + two positions per MMSI
    assert receiver._message_count == 6
    assert len(receiver._vessels) == 2
    assert len(detections) == 6
    assert len({row["target_id"] for row in targets}) == 2
    assert all(row["patch"]["location"]["source"] == "ais_reported"
               for row in targets if "location" in row["patch"])
    assert all(not row["location_valid"] for row in detections if row["message_type"] == 5)
    assert len(manager.artifacts) == 2
    for files, *_ in manager.artifacts:
        assert all(Path(p).stat().st_size > 0 for p in files)


def test_real_pyais_roundtrip_if_available():
    # This verifies real AIS payload/fragment handling only on systems with pyais.
    pyais = pytest.importorskip("pyais")
    from scripts.ais_codec import encode_position, encode_static
    parser = AISMessageAssembler()
    rows = [parser.push(frame) for frame in encode_position("200000001", 37.79, -122.36, 8.0, 35.0, "A")]
    result = next((row for row in rows if row), None)
    assert result and result["mmsi"] == "200000001"
    assert abs(result["latitude"] - 37.79) < 0.0001
    assert abs(result["longitude"] + 122.36) < 0.0001
    static = [parser.push(frame) for frame in encode_static("200000001", "FISSURE DEMO", "B")]
    assert next((row for row in static if row), None)["ship_name"] == "FISSURE DEMO"


def test_iq_file_operation_bridge_and_artifact(fake_pyais, monkeypatch, tmp_path):
    """Stub the GNU Radio child, test the real AIS Operation/callback/file path."""
    import_operations(monkeypatch)
    import importlib.util
    spec = importlib.util.spec_from_file_location("test_ais_iq_receive", ROOT / "operations" / "ais_iq_receive.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manager = FakeArtifactManager(tmp_path)
    detections, targets, statuses = [], [], []
    first = fake_encode_dict({"type": 5, "mmsi": 200000001, "shipname": "DEMO"}, "A")
    second = fake_encode_dict({"type": 1, "mmsi": 200000001, "lat": 37.7, "lon": -122.2}, "A")
    lines = first + second
    fake_child = tmp_path / "mock_gnuradio_decoder.py"
    fake_child.write_text("import sys\nfor line in %r:\n print(line, flush=True)\n" % lines, encoding="utf-8")
    iq_file = tmp_path / "capture.cf32"
    iq_file.write_bytes(b"\0" * 800)

    async def detection(row):
        detections.append(row)

    async def target(**row):
        targets.append(row)

    async def status(message):
        statuses.append(message)

    op = module.OperationMain(iq_file=str(iq_file), node_uid="node-test", save_artifact=True,
                              sample_rate=200000, center_frequency=162000000, channel="both",
                              detection_callback=detection, target_callback=target,
                              status_callback=status, artifact_manager=manager)
    op._decoder_command = lambda path: [sys.executable, "-u", str(fake_child)]
    asyncio.run(op.run())
    assert op._message_count == 2
    assert len(detections) == 2
    assert len({r["target_id"] for r in targets}) == 1
    assert manager.artifacts[0][3]["iq_format"] == "complex64_le_interleaved_iq"
    assert manager.artifacts[0][3]["nmea_messages"] == 2
    assert manager.artifacts[0][3]["backend"].startswith("gr-ais")
    assert any("complete" in x for x in statuses)


def test_iq_decoder_failure_status_and_artifact(fake_pyais, monkeypatch, tmp_path):
    import_operations(monkeypatch)
    import importlib.util
    spec = importlib.util.spec_from_file_location("test_ais_iq_error", ROOT / "operations" / "ais_iq_receive.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fake_child = tmp_path / "mock_bad_decoder.py"
    fake_child.write_text("import sys\nprint('missing gr-ais', file=sys.stderr)\nsys.exit(3)\n", encoding="utf-8")
    iq_file = tmp_path / "capture.cf32"
    iq_file.write_bytes(b"\0" * 800)
    manager = FakeArtifactManager(tmp_path)
    statuses = []
    op = mod.OperationMain(iq_file=str(iq_file), status_callback=statuses.append,
                           artifact_manager=manager)
    op._decoder_command = lambda path: [sys.executable, "-u", str(fake_child)]
    with pytest.raises(RuntimeError, match="missing gr-ais"):
        asyncio.run(op.run())
    assert manager.artifacts[0][3]["completion_reason"] == "error"
    assert any("decode error" in status for status in statuses)


def test_iq_decoder_clean_stop(fake_pyais, monkeypatch, tmp_path):
    import_operations(monkeypatch)
    import importlib.util
    spec = importlib.util.spec_from_file_location("test_ais_iq_stop", ROOT / "operations" / "ais_iq_receive.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fake_child = tmp_path / "mock_waiting_decoder.py"
    fake_child.write_text("import time\ntime.sleep(20)\n", encoding="utf-8")
    iq_file = tmp_path / "capture.cf32"
    iq_file.write_bytes(b"\0" * 800)
    manager = FakeArtifactManager(tmp_path)
    op = mod.OperationMain(iq_file=str(iq_file), artifact_manager=manager)
    op._decoder_command = lambda path: [sys.executable, "-u", str(fake_child)]

    async def scenario():
        job = asyncio.create_task(op.run())
        await asyncio.sleep(0.2)
        op._stop = True
        await asyncio.wait_for(job, timeout=3)

    asyncio.run(scenario())
    assert manager.artifacts[0][3]["completion_reason"] == "stopped"
    assert op._proc.returncode is not None


def test_user_verified_demo_fixture():
    """The 2026-11-06 FISSURE sender/receiver artifact NMEA matched byte-for-byte."""
    fixture = ROOT / "resources" / "demo_3_vessels_5_updates.nmea"
    sentences = fixture.read_text(encoding="ascii").splitlines()
    assert len(sentences) == 21
    assert all(checksum_valid(row) for row in sentences)


def test_user_verified_demo_decodes_if_pyais_available():
    pytest.importorskip("pyais")
    fixture = ROOT / "resources" / "demo_3_vessels_5_updates.nmea"
    parser = AISMessageAssembler()
    messages = [parser.push(line) for line in fixture.read_text(encoding="ascii").splitlines()]
    messages = [msg for msg in messages if msg]
    assert len(messages) == 18
    assert len({msg["mmsi"] for msg in messages}) == 3
    assert {msg["message_type"] for msg in messages} == {1, 5}


def load_iq_helper():
    spec = importlib.util.spec_from_file_location(
        "test_ais_iq_decoder_v03", ROOT / "scripts" / "ais_iq_decoder.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_nyc_water_defaults_in_schema_and_operation(monkeypatch):
    """GUI and backend defaults agree; default simulated routes stay in the Hudson."""
    import_operations(monkeypatch)
    spec = importlib.util.spec_from_file_location("ais_actions_nyc", ROOT / "actions.py")
    sensor_mod = types.ModuleType("fissure.Sensor_Node.SensorNode")
    sensor_mod.SensorNode = type("SensorNode", (), {})
    monkeypatch.setitem(sys.modules, "fissure.Sensor_Node", types.ModuleType("fissure.Sensor_Node"))
    monkeypatch.setitem(sys.modules, "fissure.Sensor_Node.SensorNode", sensor_mod)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    schema = {row["name"]: row["default"] for row in mod.ais_nmea_udp_simulate_schema["params"]}
    assert schema["base_latitude"] == 40.722
    assert schema["base_longitude"] == -74.020
    import ais_simulate
    op = ais_simulate.OperationMain(send_udp=False)
    assert (op.base_latitude, op.base_longitude) == (40.722, -74.020)
    positions = [
        (op.base_latitude + vessel * 0.008 + step * 0.0007,
         op.base_longitude + vessel * 0.0007 + step * 0.0002)
        for vessel in range(3) for step in range(5)
    ]
    # Broad sanity envelope for a short northbound Hudson River demo, not
    # geographic shoreline or chart verification.
    assert all(40.72 < lat < 40.75 and -74.025 < lon < -74.012
               for lat, lon in positions)


def test_gr38_namespace_and_probe(monkeypatch, capsys):
    """A 3.8 runtime uses import ais / ais_rx, never gnuradio.ais or 3.10 core."""
    helper = load_iq_helper()
    gr = types.ModuleType("gnuradio.gr")
    gr.version = lambda: "3.8.5.0"
    gnuradio = types.ModuleType("gnuradio")
    gnuradio.gr = gr
    ais = types.ModuleType("ais")
    ais.ais_rx = lambda *args: object()
    ais.pdu_to_nmea = lambda *args: object()
    monkeypatch.setitem(sys.modules, "gnuradio", gnuradio)
    monkeypatch.setitem(sys.modules, "gnuradio.gr", gr)
    monkeypatch.setitem(sys.modules, "ais", ais)
    assert helper.main(["--probe"]) == 0
    assert "ais.ais_rx (3.8)" in capsys.readouterr().err


def test_gr38_iq_connections_use_correct_channel_offsets(monkeypatch):
    helper = load_iq_helper()
    made = []
    connected = []
    gnuradio = types.ModuleType("gnuradio")
    gr = types.ModuleType("gnuradio.gr")
    gr.sizeof_gr_complex = 8

    class FakeTB:
        def __init__(self, title):
            self.title = title
        def connect(self, *args):
            connected.append(args)

    gr.top_block = FakeTB
    blocks = types.ModuleType("gnuradio.blocks")
    blocks.file_source = lambda *args: ("source", args)
    gnuradio.gr, gnuradio.blocks = gr, blocks
    monkeypatch.setitem(sys.modules, "gnuradio", gnuradio)
    monkeypatch.setitem(sys.modules, "gnuradio.gr", gr)
    monkeypatch.setitem(sys.modules, "gnuradio.blocks", blocks)
    ais = types.ModuleType("ais")
    def fake_rx(freq, rate, channel):
        made.append((freq, rate, channel))
        return (freq, channel)
    ais.ais_rx = fake_rx
    tb = helper.make_top_block("/tmp/capture.cf32", 200000.0, 162000000.0,
                               "both", 8, ais)
    assert tb.title == "FISSURE AIS IQ file receiver"
    assert made == [(-25000.0, 200000.0, "A"), (25000.0, 200000.0, "B")]
    assert len(connected) == 2


def test_gr310_namespace_and_receiver_probe_without_legacy_core(monkeypatch, capsys):
    """3.10 gr-ais exposes gnuradio.ais.ais_rx without FISSURE's old graph."""
    helper = load_iq_helper()
    gr = types.ModuleType("gnuradio.gr")
    gr.version = lambda: "3.10.9.2"
    gnuradio = types.ModuleType("gnuradio")
    gnuradio.gr = gr
    ais = types.ModuleType("gnuradio.ais")
    ais.ais_rx = lambda freq, rate, designator: object()
    ais.pdu_to_nmea = lambda channel: None
    gnuradio.ais = ais
    monkeypatch.setitem(sys.modules, "gnuradio", gnuradio)
    monkeypatch.setitem(sys.modules, "gnuradio.gr", gr)
    monkeypatch.setitem(sys.modules, "gnuradio.ais", ais)
    assert helper.main(["--probe"]) == 0
    assert "gnuradio.ais.ais_rx (3.10)" in capsys.readouterr().err


def test_gr310_rejects_outdated_oot_without_hierarchical_receiver(monkeypatch, capsys):
    helper = load_iq_helper()
    gr = types.ModuleType("gnuradio.gr")
    gr.version = lambda: "3.10.9.2"
    gnuradio = types.ModuleType("gnuradio")
    gnuradio.gr = gr
    ais = types.ModuleType("gnuradio.ais")
    ais.pdu_to_nmea = lambda channel: None
    gnuradio.ais = ais
    monkeypatch.setitem(sys.modules, "gnuradio", gnuradio)
    monkeypatch.setitem(sys.modules, "gnuradio.gr", gr)
    monkeypatch.setitem(sys.modules, "gnuradio.ais", ais)
    assert helper.main(["--probe"]) == 1
    assert "Cannot import gnuradio.ais" in capsys.readouterr().err


def test_real_pyais_class_b_static_and_position_if_installed():
    pytest.importorskip("pyais")
    from scripts.ais_codec import encode_class_b_static, encode_position
    assembly = AISMessageAssembler()
    static = encode_class_b_static("200000001", "FISSURE DEMO 01", "SIM0001", "A")
    assert len(static) == 2
    assert all(checksum_valid(sentence) for sentence in static)
    decoded = [assembly.push(sentence) for sentence in static]
    assert [item["message_type"] for item in decoded] == [24, 24]
    assert decoded[0]["ship_name"] == "FISSURE DEMO 01"
    assert decoded[1]["callsign"] == "SIM0001"
    positions = encode_position("200000001", 40.722, -74.020, 6.0, 10.0, "A", message_type=18)
    assert len(positions) == 1
    row = assembly.push(positions[0])
    assert row["message_type"] == 18 and row["mmsi"] == "200000001"
    assert row["reported_position_valid"] is True


def test_simulated_and_live_target_ids_do_not_collide(fake_pyais, monkeypatch):
    receiving, _ = import_operations(monkeypatch)
    targets = []
    async def capture(**kwargs):
        targets.append(kwargs)
    sentence = fake_encode_dict({"type": 1, "mmsi": 200000001,
                                 "lat": 40.72, "lon": -74.02})[0]
    async def work():
        for is_simulated in (False, True, True):
            receiver = receiving.OperationMain(target_callback=capture,
                                               save_artifact=False,
                                               simulated_input=is_simulated)
            await receiver._receive(sentence)
    asyncio.run(work())
    assert len(targets) == 3
    assert targets[0]["target_id"] != targets[1]["target_id"]
    assert targets[1]["target_id"] == targets[2]["target_id"]
    assert targets[1]["patch"]["simulated"] is True
    assert "simulated" not in targets[0]["patch"]
