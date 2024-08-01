import fissure.utils
import logging
import os
import shutil
import zmq.auth

CERTIFICATES = "certificates"
SERVER = "server"
CLIENTS = "clients"


class CertificateGenerator:
    """Generate CURVE certificates for Fissure ZMQ Server/Clients"""

    logger: logging.Logger

    def __init__(self):
        self.logger = fissure.utils.get_logger("certificate_generator")
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
        """
        Create directory structure, removing old files/directories if present
        """
        cert_dir = self.get_certificate_directory()
        srv_dir = self.get_server_certificate_directory()
        client_dir = self.get_client_certificate_directory()

        if os.path.exists(cert_dir):
            shutil.rmtree(cert_dir)
        os.mkdir(cert_dir)
        os.mkdir(srv_dir)
        os.mkdir(client_dir)
        self.logger.debug(f"reset certificates directory structure, all existing keys deleted ({cert_dir})")

    def __generate_key_pair__(self, destination: str, name: str):
        """
        Generate a public/private key pair in the destination directory with the specified filename

        :param destination: path to directory where the key pair will be placed
        :type destination: str
        :param name: name to use when generate the key files
        :type name: str
        """
        public_key, private_key = zmq.auth.create_certificates(CERTIFICATES, name)
        shutil.move(public_key, os.path.join(CERTIFICATES, destination, os.path.basename(public_key)))
        shutil.move(private_key, os.path.join(CERTIFICATES, destination, os.path.basename(private_key)))
        self.logger.debug(f"generated key pair for {name} ({destination})")

    def create_server_certificates(self):
        """
        Generate a public/private key pair for the server
        """
        self.__generate_key_pair__(destination=SERVER, name=SERVER)

    def create_client_certificates(self):
        """
        Generate a public/private key pair for the next client id
        """
        new_client_id = None
        existing_clients = [
            int(c.strip("client_").strip(".key"))
            for c in os.listdir(os.path.join(CERTIFICATES, CLIENTS))
            if c.endswith(".key")
        ]
        if len(existing_clients) == 0:
            new_client_id = 0
        else:
            new_client_id = max(existing_clients) + 1

        self.__generate_key_pair__(destination=CLIENTS, name=f"client_{new_client_id}")
