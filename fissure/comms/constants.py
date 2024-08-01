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
    DASHBOARD = "Dashboard"
    PD = "PD"
    TSI = "TSI"
    SENSOR_NODE = "Sensor Node"
    SENSOR_NODE_0 = "Sensor Node 0"
    SENSOR_NODE_1 = "Sensor Node 1"
    SENSOR_NODE_2 = "Sensor Node 2"
    SENSOR_NODE_3 = "Sensor Node 3"
    SENSOR_NODE_4 = "Sensor Node 4"


class MessageFields:
    # Generic
    IDENTIFIER = "Identifier"
    MESSAGE_NAME = "MessageName"

    # Heartbeats
    HEARTBEAT = "Heartbeat"
    TIME = "Time"
    IP = "IP"

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
