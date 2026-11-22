#!/usr/bin/env python3
"""Regression tests for the dependency direction between fissure.utils and fissure.comms.

``fissure.comms`` imports ``fissure.utils`` (FissureZMQNode reads
``fissure.utils.CERT_DIR`` at class-definition time), so a module-level
``import fissure.comms`` inside ``fissure.utils`` makes the whole
``fissure.utils`` package unimportable on a fresh interpreter. Each import is
run in a subprocess so the check cannot be satisfied by sys.modules state left
behind by another test.
"""

import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    "statement",
    [
        "import fissure.utils",
        "from fissure.utils.artifacts import Artifact",
        "from fissure.utils import protocol_crc",
        "from fissure.utils.tak_messages import send",
    ],
)
def test_utils_imports_without_prior_comms_import(statement):
    """Importing fissure.utils must not require fissure.comms to be loaded first."""
    completed = subprocess.run(
        [sys.executable, "-c", statement],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, (
        f"{statement} failed on a fresh interpreter:\n"
        f"{completed.stdout}{completed.stderr}"
    )


def test_tak_messages_imports_without_pulling_in_comms():
    """The utils package must not import the comms layer at module import time."""
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, fissure.utils.tak_messages as m; "
            "print('fissure.comms' in sys.modules); "
            "print(hasattr(m, 'send'))",
        ],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    loaded_comms, has_send = completed.stdout.split()
    assert loaded_comms == "False", "importing tak_messages must not import fissure.comms"
    assert has_send == "True", "tak_messages.send must remain available"
