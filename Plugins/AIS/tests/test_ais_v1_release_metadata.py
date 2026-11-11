"""Guard the first public AIS release metadata and README contents."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_public_release_version_and_hot_reload_markers():
    manifest = (ROOT / "plugin.yaml").read_text(encoding="utf-8")
    assert 'version: "1.0"' in manifest
    for rel in (
        "operations/ais_iq_loopback.py", "operations/ais_iq_receive.py",
        "operations/ais_osmosdr_receive.py", "operations/ais_receive.py",
        "operations/ais_sdr_receive.py", "scripts/ais_codec.py",
    ):
        source = (ROOT / rel).read_text(encoding="utf-8")
        assert 'ais-plugin-2026-11-10-v1.0' in source
        assert 'ais-plugin-2026-11-10-v0.9.27' not in source


def test_v1_readme_documents_actual_actions():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    action_src = (ROOT / "actions.py").read_text(encoding="utf-8")
    assert "v1.0" in readme
    for name in (
        "ais_usrp_b210_receive", "ais_hackrf_receive", "ais_rtlsdr_receive",
        "ais_usrp_b210_transmit", "ais_hackrf_transmit", "ais_b210_loopback",
        "ais_nmea_udp_file_receive", "ais_nmea_udp_simulate",
        "ais_iq_file_decode", "ais_iq_offline_loopback",
    ):
        assert name in readme
        assert name + "_schema" in action_src
    assert "161.975 MHz" in readme and "162.025 MHz" in readme
    assert "no" in readme.lower() and "manual frequency-correction" in readme
