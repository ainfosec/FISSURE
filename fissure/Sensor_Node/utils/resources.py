#! /usr/bin/env python3
"""Sensor Node Resource Management"""

from datetime import datetime, timezone
import logging
import os
from typing import Union

def cleanup_stale_resource_locks(logger: logging.Logger = None) -> list:
    """Remove stale FISSURE resource locks left in /tmp."""
    logger = logger if logger is not None else logging.getLogger(__name__)
    current_pid = os.getpid()
    removed = []

    try:
        entries = list(os.scandir("/tmp"))
    except OSError as exc:
        logger.warning(f"Unable to scan /tmp for FISSURE resource locks: {exc}")
        return removed

    for entry in entries:
        if not entry.is_file() or not entry.name.endswith(".lock"):
            continue

        try:
            with open(entry.path, "r") as lock_file:
                contents = lock_file.read()
        except OSError:
            continue

        if "fissure_op_id:" not in contents or "pid:" not in contents:
            continue

        lock_pid = None
        for line in contents.splitlines():
            if line.startswith("pid:"):
                try:
                    lock_pid = int(line.split(":", 1)[1].strip())
                except (TypeError, ValueError):
                    lock_pid = None
                break

        owner_alive = False
        if lock_pid is not None and lock_pid != current_pid:
            try:
                os.kill(lock_pid, 0)
                owner_alive = True
            except ProcessLookupError:
                owner_alive = False
            except PermissionError:
                owner_alive = True
            except OSError:
                owner_alive = False

        if owner_alive:
            logger.debug(
                f"Preserving active FISSURE resource lock: "
                f"{entry.path} (pid={lock_pid})"
            )
            continue

        try:
            os.remove(entry.path)
            removed.append(entry.path)
            logger.info(
                f"Removed stale FISSURE resource lock: "
                f"{entry.path} (pid={lock_pid})"
            )
        except OSError as exc:
            logger.warning(
                f"Unable to remove stale FISSURE resource lock "
                f"{entry.path}: {exc}"
            )

    return removed


class Resource(object):
    """
    Represents a resource allocated to a sensor node operation.
    """
    def __init__(self, pid: str, op_uuid: str, type: str, model: Union[str, None] = None, serial: Union[str, None] = None, logger: logging.Logger = None) -> None:
        """
        Initialize the resource parameters.

        Parameters
        ----------
        pid : str
            The process ID of the operation.
        op_uuid : str
            The unique identifier for the operation.
        type : str
            The type of the resource (e.g., 'sdr', 'file', etc.).
        model : str, optional
            The model of the resource (e.g., 'usrp b2x0', 'hackrf', etc.). If not applicable, it can be None.
        serial : str, optional
            The serial number of the resource. If not applicable, it can be None.
        """
        try:
            self.logger = logger if logger is not None else logging.getLogger(__name__)
            self.pid = pid
            self.op_uuid = op_uuid
            self.type = type
            self.model = model
            self.serial = serial
            self.allocated = False

            # get the lock filename
            type_str = str(type).replace(' ', '_').replace('-', '_').lower()
            if model is None or model == '':
                model_str = ''
            else:
                model_str = '_' + str(model).replace(' ', '_').replace('-', '_').lower()
            if serial is None or serial == '':
                serial_str = ''
            else:
                serial_str = '_' + str(serial).replace(' ', '_').replace('-', '_').lower()
            self.lock_filename = f"/tmp/{type_str}{model_str}{serial_str}.lock"
        except Exception as e:
            if logger is not None:
                logger.error(f"Error initializing Resource: {e}")
            raise e

    def __repr__(self):
        return f"Resource(pid={self.pid}, op_uuid={self.op_uuid}, type={self.type}, model={self.model}, serial={self.serial})"

    @staticmethod
    def request_resource(pid: str, op_uuid: str, type: str, model: Union[str, None] = None, serial: Union[str, None] = None) -> 'Resource':
        """
        Request a resource for a sensor node operation.

        Parameters
        ----------
        pid : str
            The process ID of the operation.
        op_uuid : str
            The unique identifier for the operation.
        type : str
            The type of the resource to request.
        model : str, optional
            The model of the resource to request. If not applicable, it can be None.
        serial : str, optional
            The serial number of the resource to request. If not applicable, it can be None.

        Returns
        -------
        Resource
            An instance of Resource representing the requested resource.
        """
        res = Resource(pid, op_uuid, type, model, serial)
        res.allocate()
        return res

    def allocate(self) -> bool:
        """
        Allocate the resource by creating a lock file.

        This method creates a lock file to indicate that the resource is allocated.

        Returns
        -------
        bool
            True if the resource was successfully allocated, False otherwise.
        """
        if os.path.exists(self.lock_filename):
            self.logger.warning(f"Resource lock file already exists: {self.lock_filename}")
            return False

        else:
            with open(self.lock_filename, 'w') as lock_file:
                lock_file.write(f"pid: {self.pid}\nfissure_op_id: {self.op_uuid}\ncreated: {datetime.now(timezone.utc).isoformat()}\n")
            self.allocated = True
            return True

    def release(self) -> None:
        """
        Release the resource by removing the lock file.

        This method removes the lock file to indicate that the resource is no longer allocated.
        """
        if os.path.exists(self.lock_filename):
            os.remove(self.lock_filename)
        else:
            self.logger.warning(f"Resource lock file does not exist: {self.lock_filename}")

def resource_available(type: str, model: Union[str, None] = None, serial: Union[str, None] = None) -> bool:
    """
    Check if a resource is available.

    Parameters
    ----------
    type : str
        The type of the resource to check.
    model : str, optional
        The model of the resource to check. If not applicable, it can be None.
    serial : str, optional
        The serial number of the resource to check. If not applicable, it can be None.

    Returns
    -------
    bool
        True if the resource is available, False otherwise.
    """
    res = Resource(None, None, type, model, serial)
    return not os.path.exists(res.lock_filename)