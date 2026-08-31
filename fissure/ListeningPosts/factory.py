def create_listening_post_runtime(
    post_type,
    *,
    component,
    post_id,
    name,
    parameters,
    loop,
    message_callback,
    activity_callback,
):
    """Create one transport implementation without importing unused optional backends."""
    if post_type == "TCP/UDP":
        from .tcp_udp import TCPUDPListeningPost
        cls = TCPUDPListeningPost
    elif post_type == "ZMQ SUB":
        from .zmq_sub import ZMQSubscriberListeningPost
        cls = ZMQSubscriberListeningPost
    elif post_type == "Website Poller":
        from .website_poller import WebsitePollerListeningPost
        cls = WebsitePollerListeningPost
    elif post_type == "Serial Port":
        from .serial_port import SerialPortListeningPost
        cls = SerialPortListeningPost
    elif post_type == "Filesystem":
        from .filesystem import FilesystemListeningPost
        cls = FilesystemListeningPost
    elif post_type == "MQTT":
        from .mqtt import MQTTListeningPost
        cls = MQTTListeningPost
    elif post_type == "Meshtastic":
        from .meshtastic import MeshtasticListeningPost
        cls = MeshtasticListeningPost
    else:
        raise RuntimeError(f"Unsupported Listening Post type: {post_type}")

    return cls(
        component,
        post_id,
        name,
        parameters,
        loop,
        message_callback,
        activity_callback,
    )
