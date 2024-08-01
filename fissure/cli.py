# from fissure import Dashboard, HiprFisr, ProtocolDiscovery, Server, TargetSignalIdentification
from fissure.comms.CertificateGenerator import CertificateGenerator
from multiprocessing import Process

import fissure.Dashboard
import fissure.Server
import fissure.utils

DELAY = 0.25


def run_all():
    # Create process objects
    backend = Process(target=fissure.Server.run, name="Backend")
    frontend = Process(target=fissure.Dashboard.run, name="Frontend")

    # Start Components (spawn processes)
    backend.start()
    frontend.start()

    # Wait for processes to shutdown
    is_alive = True
    while is_alive:
        backend.join(timeout=DELAY)
        frontend.join(timeout=DELAY)

        is_alive = backend.is_alive() or frontend.is_alive()


def run_dashboard():
    fissure.Dashboard.run()


def run_server():
    fissure.Server.run()


def run_hiprfisr():
    fissure.Server.HiprFisr.run()


def run_protocol_discovery():
    fissure.Server.ProtocolDiscovery.run()


def run_target_signal_identification():
    fissure.Server.TargetSignalIdentification.run()


def run_sensor_node():
    pass


def generate_certs():
    CG = CertificateGenerator()
    CG.create_server_certificates()
    CG.create_client_certificates()


def main():
    """
    TODO:
        - Spawn off threads for each fissure component
        - import argparse, setup args to specify which components should be run locally
            - others can be connected to remotely
    """
    # run_all()
    generate_certs()


if __name__ == "__main__":
    main()
