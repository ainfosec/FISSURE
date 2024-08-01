import threading
import asyncio


async def addBlacklist(component: object, start_frequency=0, end_frequency=0):
    """
    Specifies a frequency range to not perform TSI on.
    """
    # Add to Blacklist
    component.blacklist.append((float(start_frequency), float(end_frequency)))


async def removeBlacklist(component: object, start_frequency=0, end_frequency=0):
    """
    Removes an existing blacklisted frequency range for TSI.
    """
    remove_tuple = (float(start_frequency), float(end_frequency))

    # Remove from List
    for t in component.blacklist:
        if t == remove_tuple:
            component.blacklist.remove(t)


async def startTSI_Conditioner(
    component: object,
    sensor_node_id=0,
    common_parameter_names=[],
    common_parameter_values=[],
    method_parameter_names=[],
    method_parameter_values=[],
):
    """
    Accepts a Start message from the HIPRFISR and begins the new thread.
    """
    # Run Event and Do Not Block
    component.conditioner_running = True
    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        None, 
        component.startTSI_ConditionerThread, 
        common_parameter_names,
        common_parameter_values,
        method_parameter_names,
        method_parameter_values,
    )


async def stopTSI_Conditioner(component: object, sensor_node_id=0):
    """
    Accepts a Stop message from the HIPRFISR to stop the signal conditioning operation.
    """
    # Stop the Thread
    component.logger.info("Stopping TSI Conditioner...")
    component.conditioner_running = False


async def startTSI_FE(component: object, common_parameter_names=[], common_parameter_values=[]):
    """
    Accepts a Start message from the HIPRFISR and begins the new thread.
    """
    # Run Event and Do Not Block
    component.fe_running = True
    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        None, 
        component.startTSI_FE_Thread,  
        common_parameter_names,
        common_parameter_values,
    )
    
    
async def stopTSI_FE(component: object):
    """
    Accepts a Stop message from the HIPRFISR to stop the feature extractor operation.
    """
    # Stop the Thread
    component.logger.info("Stopping TSI Feature Extractor...")
    component.fe_running = True


async def updateLoggingLevels(component: object, new_console_level="", new_file_level=""):
    """ 
    Update the logging levels for TSI.
    """
    # Update New Levels for TSI
    component.updateLoggingLevels(new_console_level, new_file_level)

                
async def updateFISSURE_Configuration(component: object, settings_dict={}):
    """ 
    Reload fissure_config.yaml after changes.
    """
    # Update FGE Dictionary
    component.fissure_settings = settings_dict
    