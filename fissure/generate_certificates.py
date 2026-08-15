from fissure.comms.CertificateGenerator import CertificateGenerator


def generate_certs():
    generator = CertificateGenerator()
    generator.create_server_certificates()
    generator.create_client_certificates()


def main():
    generate_certs()


if __name__ == "__main__":
    main()