   ExternalExample is optional. Launch from repo root with HIPRFISR already up:
       python3 examples/external_component.py

   Default endpoint is hiprfisr.backend in YAML/fissure_config.yaml, typically
   a local IPC backend. For TCP, configure HIPRFISR backend ROUTER to bind an
   authenticated TCP endpoint; merely passing --host to the client does NOT
   expose or enable a remote server. Review CURVE certificates, firewall and
   which callbacks remote clients are permitted to invoke before deployment.
   The example documents the current internal FISSURE wire protocol; it is
   not a stabilized/public integration API.
