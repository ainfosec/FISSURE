import logging
import os
import shutil

import zmq.auth


CERTIFICATES = "certificates"
SERVER = "server"
CLIENTS = "clients"


class CertificateGenerator:
    """Generate CURVE certificates for FISSURE ZMQ servers and clients."""

    def __init__(self):
        self.logger = logging.getLogger("certificate_generator")
        self.__reset_directory_structure__()

    @classmethod
    def get_certificate_directory(cls):
        return os.path.join(os.getcwd(), CERTIFICATES)

    @classmethod
    def get_server_certificate_directory(cls):
        return os.path.join(cls.get_certificate_directory(), SERVER)

    @classmethod
    def get_client_certificate_directory(cls):
        return os.path.join(cls.get_certificate_directory(), CLIENTS)

    def __reset_directory_structure__(self):
        cert_dir = self.get_certificate_directory()

        if os.path.exists(cert_dir):
            shutil.rmtree(cert_dir)

        os.makedirs(self.get_server_certificate_directory())
        os.makedirs(self.get_client_certificate_directory())

        self.logger.debug(
            "Reset certificate directory structure; existing keys were deleted (%s)",
            cert_dir,
        )

    def __generate_key_pair__(self, destination: str, name: str):
        public_key, private_key = zmq.auth.create_certificates(CERTIFICATES, name)

        shutil.move(
            public_key,
            os.path.join(CERTIFICATES, destination, os.path.basename(public_key)),
        )
        shutil.move(
            private_key,
            os.path.join(CERTIFICATES, destination, os.path.basename(private_key)),
        )

        self.logger.debug("Generated key pair for %s (%s)", name, destination)

    def create_server_certificates(self):
        self.__generate_key_pair__(destination=SERVER, name=SERVER)

    def create_client_certificates(self):
        existing_clients = [
            int(filename.removeprefix("client_").removesuffix(".key"))
            for filename in os.listdir(self.get_client_certificate_directory())
            if filename.startswith("client_") and filename.endswith(".key")
        ]

        new_client_id = max(existing_clients, default=-1) + 1
        self.__generate_key_pair__(
            destination=CLIENTS,
            name=f"client_{new_client_id}",
        )