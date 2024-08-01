from typing import Dict, Union

# Config Keys
PROTOCOL = "protocol"
ADDRESS = "address"
HB_CHANNEL = "heartbeat_channel"
MSG_CHANNEL = "message_channel"

# Protocols
TCP = "tcp"
IPC = "ipc"


class Address:
    __config: Dict[str, Union[str, int]]
    protocol: str
    address: str
    heartbeat_channel: str
    message_channel: str

    def __init__(
        self,
        address_config: Dict[str, str] = None,
        protocol: str = None,
        address: str = None,
        hb_channel: str = None,
        msg_channel: str = None,
    ):
        """
        FISSURE Server Address Object, requires supplying either:
            address_config OR protocol, address, hb_channel, msg_channel

        :param address_config: address data, defaults to None
        :type address_config: Dict[str, str], optional
        :param protocol: address protocol (tcp or ipc), defaults to None
        :type protocol: str, optional
        :param address: base address (IP address or path to IPC socket), defaults to None
        :type address: str, optional
        :param hb_channel: channel to use for heartbeats, defaults to None
        :type hb_channel: str, optional
        :param msg_channel: channel to use for messages (Commands/Status), defaults to None
        :type msg_channel: str, optional
        """
        # if address pieces are passed in raw, create the dict
        if address_config is None:
            address_config = {PROTOCOL: protocol, ADDRESS: address, HB_CHANNEL: hb_channel, MSG_CHANNEL: msg_channel}

        self.__config = address_config
        self.__parse_address__()

    def __parse_address__(self):
        """
        parse the address config dictionary and set the channels accordingly
        """
        self.protocol = self.__config.get(PROTOCOL)
        self.address = self.__config.get(ADDRESS)

        if self.protocol == TCP:
            hb_port = self.__config.get(HB_CHANNEL)
            self.heartbeat_channel = f"{self.protocol}://{self.address}:{hb_port}"
            msg_port = self.__config.get(MSG_CHANNEL)
            self.message_channel = f"{self.protocol}://{self.address}:{msg_port}"

        elif self.protocol == IPC:
            self.heartbeat_channel = f"{self.protocol}://{self.address}-hb"
            self.message_channel = f"{self.protocol}://{self.address}-msg"

    def __str__(self) -> str:
        base_address = f"{self.protocol}://{self.address}"
        return (
            f"{base_address} [{self.heartbeat_channel.replace(base_address, '')} (hb), "
            + f"{self.message_channel.replace(base_address, '')} (msg)]"
        )

    def __eq__(self, other) -> bool:
        if not isinstance(other, Address):
            return False

        return self.__config == other.__config

    def __hash__(self) -> int:
        return hash(str(self))

    def update(self, **kwargs):
        """
        Update the Address Data

        Mirrors the `.update()` method for dicts
        """
        self.__config.update(kwargs)
        self.__parse_address__()
