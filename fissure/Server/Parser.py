import argparse

LOCAL_ADDRESS = "ipc://fissure-hiprfisr"

DEFAULT_HEARTBEAT_PORT = 5051
DEFAULT_MESSAGE_PORT = 5052


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument("-r", "--remote", action="store_true")
    parser.add_argument("-H", "--heartbeat_port", type=int, default=DEFAULT_HEARTBEAT_PORT)
    parser.add_argument("-M", "--message_port", type=int, default=DEFAULT_MESSAGE_PORT)

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    print(args)
