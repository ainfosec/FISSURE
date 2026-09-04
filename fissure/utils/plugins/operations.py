#! /usr/bin/env python3
"""Plugin Operations Related Functionality
"""
import asyncio
import inspect
from inspect import signature, _empty
import logging
import os
import uuid
import re
import sys
from typing import Dict, Any, Union, Callable

from fissure.Sensor_Node.utils.resources import Resource
from fissure.utils.artifacts import ArtifactManager, get_artifact_manager

_base_params = [
    'self', 
    'node_uid', 
    'logger', 
    'alert_callback', 
    'tak_cot_callback', 
    'detection_callback', 
    'status_callback', 
    'target_callback', 
    'soi_callback', 
    'recommendation_callback', 
    'artifact_manager'
]

async def send_alert(node_uid="", opid="", message="", logger=logging.getLogger(__name__)) -> None:
    """Placeholder alert callback used when an operation runs outside a Sensor Node."""
    if isinstance(node_uid, dict):
        logger.info(f"Alert: {node_uid}")
        return

    logger.info(f"Alert {node_uid}, {opid}: {message}")


async def send_detection(detection: Dict[str, Any], logger=logging.getLogger(__name__)) -> None:
    """Placeholder for detection callback if none is provided.

    Parameters
    ----------
    detection : Dict[str, Any]
        Structured detection emitted by a detector operation.
    """
    logger.info(f"Detection: {detection}")


async def send_tak_cot(node_uid: str, opid: str, uid: str, remarks: str, lat: Union[float, bool] = True, lon: Union[float, bool] = True, alt: Union[float, bool] = True, time: Union[float, bool] = True, type: str="a-f-G-U-H", logger=logging.getLogger(__name__)) -> None:
    """Placeholder for TAK CoT callback if none is provided.

    Parameters
    ----------
    node_uid : str
        The sensor node UID
    opid : str
        The operation ID
    uid : str
        The unique ID
    remarks : str
        The remarks
    lat : Union[float, bool], optional
        The latitude, by default True
    lon : Union[float, bool], optional
        The longitude, by default True
    alt : Union[float, bool], optional
        The altitude, by default True
    time : Union[float, bool], optional
        The time, by default True
    type : str, optional
        The type, by default "a-f-G-U-H"
    """
    logger.info(f"TAK CoT {node_uid}, {opid}: uid={uid}, lat={lat}, lon={lon}, alt={alt}, time={time}, type={type}, remarks={remarks}")

async def send_status(node_uid, opid, status_text, logger=None):
    if logger:
        logger.info(f"[status] {node_uid} {opid}: {status_text}")

async def send_target(node_uid, opid, target_dict, logger=None):
    if logger:
        logger.info(f"[target] {node_uid} {opid}: {target_dict}")

async def send_soi(node_uid, opid, soi_dict, logger=None):
    if logger:
        logger.info(f"[soi] {node_uid} {opid}: {soi_dict}")

async def send_recommendation(target_id, recommendation, logger=None):
    if logger:
        logger.info(f"[recommendation] target={target_id}: {recommendation}")

def setup_decorator(func):
    async def wrapper(self) -> bool:
        self.logger.info("Setting up operation environment...")

        # allocate resources
        self._resources = [] # track resources that were successfully allocated
        for res in self.resources:
            if not res.allocated:
                if not res.allocate():
                    self.logger.error(f"Failed to allocate resource: {res}")
                    self.logger.info("Operation environment setup failed.")
                    await self.teardown()
                    return False
                self._resources.append(res)
                self.logger.info(f"Allocated resource: {res}")

        # call the decorated setup function
        status = await func(self)

        if not status:
            self.logger.info("Operation environment setup failed.")
            await self.teardown()
            return False
        
        # create flag to indicate successful setup
        self._setup_complete = True
        self.logger.info("Operation environment setup complete.")
        return True
    return wrapper

def run_decorator(func):
    """Decorator to wrap the run() method of Operation class."""
    async def wrapper(self) -> None:
        self._running = None
        if not self._setup_complete:
            self.logger.error("Operation environment not set up. Call setup() before run().")
            return

        self.logger.info(f"Operation {self.__class__.__name__} run started.")
        self._running = True

        try:
            self.logger.info(f"Running operation {self.__class__.__name__}...")
            await func(self)
        except asyncio.CancelledError:
            # Cancellation is a stop condition, not an operation failure. Most
            # importantly, never leave running() stuck True after cancellation.
            self._stop = True
            raise
        except Exception as e:
            self.logger.error(f"Error during operation run: {e}")
        finally:
            self._running = False

        self.logger.info(f"Operation {self.__class__.__name__} run complete.")
        return
    return wrapper

def stop_decorator(func) -> Callable:
    async def wrapper(self) -> None:
        self.logger.info(f"Stopping {self.__class__.__name__}...")
        self._stop = True
        while self.running():
            await asyncio.sleep(0.1)
            self.logger.debug(f"Waiting for {self.__class__.__name__} to stop...")
        await func(self)
        self.logger.info(f"{self.__class__.__name__} stopped.")
    return wrapper

def teardown_decorator(func) -> Callable:
    async def wrapper(self) -> None:
        self.logger.info(f"Tearing down operation environment for {self.__class__.__name__}...")

        self._setup_complete = False

        await func(self)

        if hasattr(self, '_resources'):
            self.logger.debug(f"Releasing {len(self._resources)} resources for {self.__class__.__name__}...")
            while len(self._resources) > 0:
                try:
                    res = self._resources.pop()
                    self.logger.debug(f"Releasing resource: {res}")
                    res.release()
                except Exception as e:
                    self.logger.error(f"Error releasing resource {res}: {e}")

        self.logger.info(f"Operation environment teardown complete for {self.__class__.__name__}.")
    return wrapper

def operation_class_decorator(cls):
    """Class decorator to apply method decorators to Operation class methods.
    """
    def dec_init(self, *args, **kwargs):
        if not hasattr(self, 'logger'):
            self.logger = logging.getLogger(__name__)

        # original __init__ method
        cls.__init_original(self, *args, **kwargs)

        if not hasattr(self, 'opid'):
            self.opid = str(uuid.uuid4())  # Generate a unique operation ID

        # status tracking
        if not hasattr(self, '_setup_complete'):
            self._setup_complete = False
        if not hasattr(self, '_stop'):
            self._stop = False
        if not hasattr(self, '_running'):
            self._running = None # Use None to indicate that the operation has not started yet

        # prepare resources
        self.prepare_resources()

        # log initialization
        self.logger.debug(f"Initialized operation {self.__class__.__name__} with node_uid={self.node_uid}, opid={self.opid}")

    if not hasattr(cls, '__init_original'):
        cls.__init_original = cls.__init__
        cls.__init__ = dec_init
        cls.__init__.__doc__ = cls.__init_original.__doc__

        # Safely copy optional metadata
        if hasattr(cls.__init_original, "__type_params__"):
            cls.__init__.__type_params__ = cls.__init_original.__type_params__

        if hasattr(cls.__init_original, "__kwdefaults__"):
            cls.__init__.__kwdefaults__ = cls.__init_original.__kwdefaults__

    return cls

@operation_class_decorator
class Operation(object):
    """Base class for plugin operations.
    """
    def __init__(
            self, 
            node_uid: str = "", 
            logger: logging.Logger = logging.getLogger(__name__), 
            alert_callback: Union[Callable, None] = None, 
            tak_cot_callback: Union[Callable, None] = None, 
            detection_callback: Union[Callable, None] = None, 
            status_callback: Union[Callable, None] = None, 
            target_callback: Union[Callable, None] = None, 
            soi_callback: Union[Callable, None] = None, 
            recommendation_callback: Union[Callable, None] = None, 
            artifact_manager: Union[ArtifactManager, None] = None
        ) -> None:
        """Initialize the Operation class.

        Parameters
        ----------
        node_uid : str, optional
            The UID of the sensor node
        logger : logging.Logger, optional
            Logger instance for logging, by default logging.getLogger(__name__)
        alert_callback : Union[Callable, None], optional
            Callback function for alerts, by default None for logger-only alerts
        tak_cot_callback : Union[Callable, None], optional
            Callback function for TAK CoT messages, by default None for logger-only TAK CoT messages
        detection_callback : Union[Callable, None], optional
            Callback function for structured detections, by default None for logger-only detections
        status_callback : Union[Callable, None], optional
            Callback function for reporting status to TAK and Dashboard
        target_callback : Union[Callable, None], optional
            Callback function for reporting targets to TAK and Dashboard
        soi_callback : Union[Callable, None], optional
            Callback function for reporting SOIs to TAK and Dashboard
        recommendation_callback : Union[Callable, None], optional
            Callback function for attaching recommended follow-on actions to Targets
        artifact_manager : Union[ArtifactManager, None], optional
            ArtifactManager instance for managing artifacts, by default None to use the global artifact manager
        """
        # input parameters
        self.node_uid = node_uid
        self.logger = logger
        self.execution_context = {}
        if alert_callback is None:
            alert_callback = send_alert
        if tak_cot_callback is None:
            tak_cot_callback = send_tak_cot
        if detection_callback is None:
            detection_callback = send_detection
        if status_callback is None:
            status_callback = send_status
        if target_callback is None:
            target_callback = send_target
        if soi_callback is None:
            soi_callback = send_soi
        if recommendation_callback is None:
            recommendation_callback = send_recommendation
        self.alert_callback = alert_callback
        self.tak_cot_callback = tak_cot_callback
        self.detection_callback = detection_callback
        self.status_callback = status_callback
        self.target_callback = target_callback
        self.soi_callback = soi_callback
        self.recommendation_callback = recommendation_callback
        if artifact_manager is not None:
            self.artifact_manager = artifact_manager
        else:
            self.artifact_manager = get_artifact_manager()

        # unique operation ID
        self.opid = str(uuid.uuid4())


    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        # apply decorators to subclass methods
        setattr(cls, 'setup', setup_decorator(cls.setup))
        setattr(cls, 'run', run_decorator(cls.run))
        setattr(cls, 'stop', stop_decorator(cls.stop))
        setattr(cls, 'teardown', teardown_decorator(cls.teardown))


    def __repr__(self):
        sig = inspect.signature(self.__init__)
        params = list(sig.parameters.keys())
        for p in _base_params:
            if p in params:
                params.remove(p)
        return f"{self.__class__.__name__}(node_uid={self.node_uid}" + ''.join([f", {p}={getattr(self, p)}" for p in params]) + ")"


    def get_subprocess_environment(self) -> Dict[str, str]:
        """Build a subprocess environment for the operation execution context."""
        env = os.environ.copy()
        context = (
            self.execution_context
            if isinstance(self.execution_context, dict)
            else {}
        )

        if str(context.get("presentation") or "").strip().lower() == "xpra":
            display = str(context.get("display") or "").strip()
            if re.fullmatch(r":\d+(?:\.\d+)?", display):
                env["DISPLAY"] = display
            env["QT_QPA_PLATFORM"] = "xcb"
            env.pop("WAYLAND_DISPLAY", None)
            env.pop("XAUTHORITY", None)

        return env


    async def wait_for_graphical_display(
        self,
        timeout_s: float = 60.0,
    ) -> bool:
        """Wait for an Xpra-backed X11 display before launching a GUI."""
        context = (
            self.execution_context
            if isinstance(self.execution_context, dict)
            else {}
        )

        if str(context.get("presentation") or "").strip().lower() != "xpra":
            return True

        display = str(context.get("display") or "").strip()
        match = re.fullmatch(r":(\d+)(?:\.\d+)?", display)
        if not match:
            raise RuntimeError(
                f"Invalid Xpra display in execution context: {display!r}"
            )

        socket_path = f"/tmp/.X11-unix/X{match.group(1)}"
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(1.0, float(timeout_s))

        self.logger.info(
            f"Waiting for graphical display {display} at {socket_path}"
        )

        while not self._stop:
            if os.path.exists(socket_path):
                # Give the X server a moment to finish initialization after
                # creating its Unix-domain socket.
                await asyncio.sleep(0.25)
                self.logger.info(
                    f"Graphical display {display} is ready."
                )
                return True

            if loop.time() >= deadline:
                raise RuntimeError(
                    f"Timed out waiting for graphical display {display}."
                )

            await asyncio.sleep(0.1)

        return False


    @classmethod
    def get_arguments(cls, logger: logging.Logger = logging.getLogger(__name__)) -> Dict[str, Any]:
        """Get the arguments required to initialize the operation.

        Parameters
        ----------
        cls : Operation
            The operation class to inspect.
        logger : logging.Logger, optional
            Logger instance for logging, by default logging.getLogger(__name__)

        Returns
        -------
        Dict[str, Any]
            A dictionary specifying the arguments required to initialize the operation. The keys are argument names, and the values are dictionaries with key, value pairs with keys `default`, `type`, `description`, and `required`. All values are cast to strings to facilitate JSON serialization.
        """
        # Get the argument types of cls.__init__ method
        sig = signature(cls.__init__)
        input_types = {k: v.annotation for k, v in sig.parameters.items() if k != 'self'}

        # Get default values of cls.__init__ parameters
        sig = signature(cls.__init__)
        defaults = {}
        for name, param in sig.parameters.items():
            if name == 'self':
                continue
            if param.default is not _empty:
                defaults[name] = param.default
            else:
                defaults[name] = ''

        # Load the docstring
        docstring = cls.__init__.__doc__
        params = {}
        if not docstring:
            logger.error("No docstring found.")
            sys.exit(0)

        # Find the Parameters section
        param_section = re.search(r'Parameters\s*-+\s*(.*?)(?=\n\S|\Z)', docstring, re.DOTALL)
        if not param_section:
            logger.error("No Parameters section found in docstring. Use numpy style docstring format.")
            sys.exit(0) 

        # Split by parameter blocks
        param_blocks = re.split(r'\n(?=\s*\w+\s*:\s*)', param_section.group(1))
        params = {}
        for block in param_blocks:
            # split the parameter lines
            lines = block.strip().split('\n')
            if not lines or ':' not in lines[0]:
                continue

            # First line: param : type, optional
            first = lines[0]
            name_type_optional = first.split(':', 1)
            name = name_type_optional[0].strip()
            if name in _base_params:
                continue
            type_optional = name_type_optional[1].strip().split(',', 1)
            if len(type_optional) == 1:
                required = True
            else:
                required = 'optional' not in type_optional[1].strip().lower()

            # get the description
            desc = ' '.join(line.strip() for line in lines[1:]).strip()

            # add to params
            params[name] = {
                'default': defaults.get(name, None),
                'type': input_types.get(name, str),
                'description': desc,
                'required': required
            }

        return params

    @staticmethod
    def get_resources(*args, **kwargs) -> Dict[str, Any]:
        """Get resources for the operation

        Returns
        -------
        Dict[str, Any]
            Resources dictionary
        """
        return {}

    @staticmethod
    def get_interfaces() -> Dict[str, Any]:
        """Get the interfaces required for the operation.

        This function should be implemented in the plugin operation module to specify the interfaces required for the operation.

        Common interface types include:

        'alert': {
            'type': 'alert',
            'channel': 'fissure', # FISSURE zmq
            'direction': 'out',
            'description': 'Wifi AP detections.'
        }

        'tak': {
            'type': 'tak',
            'channel': 'fissure', # FISSURE zmq
            'direction': 'out',
            'description': 'Wifi AP detections in TAK CoT format.'
        }

        Returns
        -------
        Dict[str, Any]
            A dictionary specifying the interfaces required for the operation. The keys are interface names, and the values are dictionaries with key, value pairs (`type`, str), (`channel`, str), (`direction`, str), and (`description`, str).
        """
        return {}

    def prepare_resources(self) -> None:
        """Prepare resources for the operation.
        """
        resources = self.get_resources(**self.resource_args) if hasattr(self, 'resource_args') else self.get_resources()
        self.logger.info(f"Resources defined: {resources}")
        self.resources = [
            Resource(
                pid=str(os.getpid()),
                op_uuid=self.opid,
                type=res_info.get('type'),
                model=res_info.get('model'),
                serial=res_info.get('serial'),
                logger=self.logger
            )
        for _, res_info in resources.items()]

    async def setup(self) -> bool:
        """
        Setup the environment to run the operation.

        Setup includes allocating resources for use by the operation. The developer can override this method to implement additional setup to prepare for running the operation.

        Returns
        -------
        bool
            True if setup was successful, False otherwise.
        """
        return True

    async def run(self) -> None:
        """
        Run the operation.

        This method should be overridden by subclasses to implement the main functionality of the operation. If the operation includes loops,
        
        - the method should periodically check the `self._stop` flag to determine if it should exit gracefully
        - the method should call `await asyncio.sleep(0)` within loops to allow for cooperative multitasking
        """
        self.logger.warning("The run() method should be implemented by the subclass.")

    async def _sleep_stop_aware(self, duration_s: float, check_interval_s: float = 0.1) -> bool:
        """Sleep for a duration while remaining responsive to an operation stop request.

        Returns True when the full duration elapses, or False when ``self._stop``
        becomes set before the duration completes.
        """
        duration_s = max(0.0, float(duration_s))
        check_interval_s = max(0.01, float(check_interval_s))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + duration_s

        while not self._stop:
            remaining_s = deadline - loop.time()
            if remaining_s <= 0:
                return True

            await asyncio.sleep(min(check_interval_s, remaining_s))

        return False

    def running(self) -> bool:
        """
        Check if operation is running.

        Returns
        -------
        bool
            True if the operation is running, False otherwise.
        """
        return self._running

    async def stop(self) -> None:
        """
        Stop the operation.
        """
        return

    async def teardown(self) -> None:
        """
        Teardown the environment for the operation.
        """
        return

    def create_artifact(
        self,
        files,
        name: str,
        artifact_type: str,
        metadata: Union[dict, None] = None,
        relations=None,
        file_metadata: Union[Dict[str, Dict[str, Any]], None] = None,
    ) -> str:
        """
        Register one logical artifact containing one or more files generated by
        this operation.

        ArtifactManager owns manifest creation, file IDs, relative paths,
        checksums, sizes, totals, validation, and persistence.
        """
        if not self.artifact_manager:
            self.logger.error(
                "Artifact manager is not initialized."
            )
            return ""

        try:
            return self.artifact_manager.create_artifact(
                source_id=str(
                    self.node_uid or "sensor_node"
                ),
                operation_id=self.opid,
                files=files,
                name=name,
                artifact_type=artifact_type,
                metadata=metadata or {},
                relations=relations,
                file_metadata=file_metadata,
            )

        except Exception as exc:
            self.logger.error(
                "Failed to create artifact: %s",
                exc,
            )
            return ""

    def update_artifact(
        self,
        artifact_id: str,
        files=None,
        metadata: Union[Dict[str, Any], None] = None,
        relations=None,
        file_metadata: Union[
            Dict[str, Dict[str, Any]],
            None,
        ] = None,
    ) -> bool:
        """
        Update the files, metadata, or relations of an artifact owned by this
        operation.
        """
        if not self.artifact_manager:
            self.logger.error(
                "Artifact manager is not initialized."
            )
            return False

        artifact = self.artifact_manager.get_artifact(
            artifact_id
        )

        if artifact is None:
            self.logger.error(
                "Artifact %s not found.",
                artifact_id,
            )
            return False

        if artifact.operation_id != self.opid:
            self.logger.error(
                "Artifact %s does not belong to operation %s.",
                artifact_id,
                self.opid,
            )
            return False

        try:
            return self.artifact_manager.update_artifact(
                artifact_id=artifact_id,
                files=files,
                metadata=metadata,
                relations=relations,
                file_metadata=file_metadata,
            )

        except Exception as exc:
            self.logger.error(
                "Failed to update artifact %s: %s",
                artifact_id,
                exc,
            )
            return False
        

def main(*args, **kwargs) -> object:
    """Create an instance of the operation class.

    This function must be implemented in the plugin operation module to create and return an instance of the operation class.

    The function contents consist of a single line that creates an instance of the operation class with the provided keyword arguments and returns it, e.g.:

        return Operation(**kwargs)

    Parameters
    ----------
    **kwargs : dict
        Keyword arguments to pass to the operation class constructor.

    Returns
    -------
    object
        An instance of the operation class.
    """
    kwargs["logger"].error("The main() function must be implemented in the plugin operation module to return an instance of the operation class.")
    return None