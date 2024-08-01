from typing import List

""" Generic FISSURE Component Callback Functions """


async def shutdown(component: object, identifiers: List[str]):
    for identifier in identifiers:
        if identifier == component.identifier:
            component.logger.info("recieved shutdown command")
            component.shutdown = True
        else:
            pass
