"""FissureZMQ Keyword Constants"""


class MessageTypes:
    HEARTBEATS = "Heartbeats"
    STATUS = "Status"
    COMMANDS = "Commands"
    SOI = "SOI"
    WIDEBAND = "Wideband"
    SET = "Set"


class Identifiers:
    HIPRFISR = "HiprFisr"
    HIPRFISR_LT = "H"
    DASHBOARD = "Dashboard"
    SENSOR_NODE = "Sensor Node"


class MessageFields:
    # Generic
    IDENTIFIER = "Identifier"  # Full UUID for IP, 8 characters for Meshtastic
    MESSAGE_NAME = "MessageName"
    SOURCE = "Source"  # TODO
    DESTINATION = "Destination"  #TODO

    # Heartbeats
    #IDENTIFIER
    HEARTBEAT = "Heartbeat"  # MESSAGE_NAME
    TIME = "Time"
    IP = "IP"  # IP Only
    ASSIGNED_ID = "AssignedID"  # Meshtastic Only
    INTERVAL = "Interval"

    # Status/Commands
    CALLBACK = "callback"
    PARAMETERS = "Parameters"

    # SOI/Wideband
    MOD_TYPE = "Modulation Type"
    FREQ = "Frequency"
    PWR = "Power"
    BW = "Bandwidth"
    CONT = "Continuous"
    START_FREQ = "StartFrequency"
    END_FREQ = "End Frequency"
    TIME_STAMP = "Timestamp"
    CONF = "Confidence"

    # Set
    SET = "Set"
    VAR = "Variable"
    VAL = "Value"

    # For Parsing
    TYPE = "Type"
    SENDER_ID = "SenderID"


class Parameters:
    IDENTIFIERS = "identifiers"
