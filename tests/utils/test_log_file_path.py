#!/usr/bin/env python3
"""Tests for resolving the active FISSURE log file (issue #41)."""

import importlib.util
import logging
import os

import pytest

# Load common.py directly so these tests don't depend on the rest of fissure.utils.
_COMMON_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "fissure", "utils", "common.py")
_spec = importlib.util.spec_from_file_location("fissure_utils_common_under_test", _COMMON_PATH)
common = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(common)


@pytest.fixture
def isolated_logger():
    """A logger with no handlers, restored afterwards."""
    name = "fissure_log_path_test"
    logger = logging.getLogger(name)
    saved = list(logger.handlers)
    logger.handlers = []
    yield name, logger
    for handler in logger.handlers:
        handler.close()
    logger.handlers = saved


def _patch_yaml(monkeypatch, config):
    monkeypatch.setattr(common, "load_yaml", lambda filename: config)


def test_live_file_handler_wins(isolated_logger, tmp_path, monkeypatch):
    name, logger = isolated_logger
    live_path = tmp_path / "live.log"
    logger.addHandler(logging.FileHandler(live_path))
    _patch_yaml(monkeypatch, {"handlers": {"file": {"filename": "Logs/other.log"}}})

    assert common.get_log_file_path(name) == str(live_path)


def test_stream_handler_is_ignored(isolated_logger, monkeypatch):
    name, logger = isolated_logger
    logger.addHandler(logging.StreamHandler())
    _patch_yaml(monkeypatch, {"handlers": {"file": {"filename": "Logs/renamed.log"}}})

    assert common.get_log_file_path(name) == os.path.join(common.FISSURE_ROOT, "Logs", "renamed.log")


def test_yaml_prefers_handler_attached_to_logger(isolated_logger, monkeypatch):
    name, _ = isolated_logger
    _patch_yaml(monkeypatch, {
        "handlers": {
            "audit": {"filename": "Logs/audit.log"},
            "console": {"stream": "ext://sys.stdout"},
            "main": {"filename": "Logs/main.log"},
        },
        "loggers": {name: {"handlers": ["console", "main"]}},
    })

    assert common.get_log_file_path(name) == os.path.join(common.FISSURE_ROOT, "Logs", "main.log")


def test_yaml_falls_back_to_any_file_handler(isolated_logger, monkeypatch):
    name, _ = isolated_logger
    _patch_yaml(monkeypatch, {
        "handlers": {"console": {"stream": "ext://sys.stdout"}, "file": {"filename": "Logs/x.log"}},
        "loggers": {name: {"handlers": ["console"]}},
    })

    assert common.get_log_file_path(name) == os.path.join(common.FISSURE_ROOT, "Logs", "x.log")


@pytest.mark.parametrize("config", [None, {}, {"handlers": {"console": {"stream": "ext://sys.stdout"}}}])
def test_default_when_no_file_handler(isolated_logger, monkeypatch, config):
    name, _ = isolated_logger
    _patch_yaml(monkeypatch, config)

    assert common.get_log_file_path(name) == os.path.join(common.LOG_DIR, "event.log")


def test_default_when_yaml_missing(isolated_logger, monkeypatch):
    name, _ = isolated_logger

    def missing(filename):
        raise FileNotFoundError(filename)

    monkeypatch.setattr(common, "load_yaml", missing)

    assert common.get_log_file_path(name) == os.path.join(common.LOG_DIR, "event.log")


def test_shipped_logging_yaml_resolves_to_event_log(isolated_logger):
    name, _ = isolated_logger

    assert common.get_log_file_path(name) == os.path.join(common.FISSURE_ROOT, "Logs", "event.log")
