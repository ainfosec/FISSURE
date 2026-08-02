# FISSURE Remote Sensor Node Deployment

This directory contains the complete Apptainer-based deployment workflow for a
remote FISSURE Sensor Node. Run all commands below from the FISSURE repository
root.

The deployer builds or reuses a local SIF, renders deployment configuration
with Jinja2, stages the installed certificates, transfers the payload over SSH,
and installs a rollback-aware systemd service on the target.

## Quick start

Install the deployment-only Python dependencies:

```bash
python3 -m pip install -r \
  Installer/Remote_Sensor_Node/requirements-node-deploy.txt
```

Start the local FISSURE Dashboard, then deploy by providing only the target IP:

```bash
Installer/Remote_Sensor_Node/deploy_remote_sensor_node.py 192.0.2.20
```

An IP-only target uses the remote `root` account. Without `-i`, the deployer
securely prompts for the SSH password.

To use a non-root account and an SSH key:

```bash
Installer/Remote_Sensor_Node/deploy_remote_sensor_node.py \
  fissure@192.0.2.20 -i ~/.ssh/fissure-node
```

The deployer tries passwordless `sudo` after connecting as a non-root user. If
that is unavailable, it securely prompts for the sudo password.
During SCP, each file reports its percentage and transferred/total size. The
multi-gigabyte SIF therefore remains visibly active throughout the upload.

## Templates and local inputs

The complete deployment configuration is visible under `templates/`:

- `sensor-node.yml.j2` renders the remote Sensor Node YAML.
- `fissure-sensor-node.service.j2` renders the installed systemd unit.
- `remote_sensor_node_apptainer.def.j2` renders the local image definition.

Jinja2 uses strict undefined-variable handling, so an incomplete template
context stops deployment instead of emitting a partially configured file.
The source values for `sensor-node.yml.j2` come from the current FISSURE
installation by default:

By default, inputs come from the current FISSURE installation:

- `YAML/Sensor_Node_Config/default.yaml`
- `certificates/clients/client_0.key_secret`
- `certificates/server/server.key`
- `Installer/Remote_Sensor_Node/build/fissure-sensor-node.sif`

The SIF is reused when present. Otherwise, the deployer installs local
Apptainer when permitted and builds the image before opening SSH. Use `--image`
to select another SIF, or `--no-install-apptainer` to prohibit automatic local
and remote package installation.

Rendered configuration and certificates are transferred separately and
bind-mounted read-only. They are never baked into the SIF. Rendering preserves
the installed Sensor Node values and replaces only a loopback HIPRFISR address
with the local endpoint of the established SSH connection. It performs no host
discovery and does not change the installed source YAML. Certificates remain
ordinary external files because secrets must never be placed in templates.

## Operations

Check an existing deployment without changing it:

```bash
Installer/Remote_Sensor_Node/deploy_remote_sensor_node.py \
  192.0.2.20 --health-only
```

Remove the remote service and deployment state:

```bash
Installer/Remote_Sensor_Node/deploy_remote_sensor_node.py \
  192.0.2.20 --uninstall
```

Uninstall preserves the remote Apptainer package and local cached SIF. Use
`--startup-only` to accept process startup without a HIPRFISR heartbeat when
intentionally staging a node before its hub is reachable.

Run the command with `--help` for configuration, image, service, overlay, and
health-timeout options.
The default 180-second health window covers heavyweight SensorNode imports.
For IP nodes, readiness accepts either an inbound HIPRFISR heartbeat or a fresh
matching heartbeat receipt in the local HIPRFISR event log.

## Safety and lifecycle

A full deployment requires the local FISSURE Dashboard process to be running.
The check occurs before image building, credential prompts, or SSH. Health and
uninstall operations remain available without the Dashboard.

Each deployment creates a timestamped remote release. Configuration,
certificates, logs, the writable overlay, and node identity remain outside the
SIF. The service is promoted only after process and heartbeat validation; a
failed upgrade restores the previous release.
Service startup rechecks configuration and certificates without recursively
importing heavyweight runtime modules already validated during the image build.

The default remote installation root is `/opt/fissure-sensor-node`.

## Directory contents

| File | Purpose |
| --- | --- |
| `deploy_remote_sensor_node.py` | CLI entrypoint and deployment orchestration |
| `remote_sensor_node_config.py` | Remote configuration staging |
| `remote_sensor_node_deploy_utilities.py` | Remote lifecycle shell scripts |
| `remote_sensor_node_image_check.py` | Image and runtime prerequisite checks |
| `remote_sensor_node_local_apptainer.py` | Local Apptainer installation |
| `remote_sensor_node_local_fissure.py` | Local Dashboard preflight |
| `remote_sensor_node_privilege.py` | Remote sudo and package preparation |
| `remote_sensor_node_health.py` | End-to-end heartbeat readiness checks |
| `remote_sensor_node_scp.py` | Interactive and log-friendly SCP progress |
| `remote_sensor_node_templates.py` | Strict Jinja2 rendering boundary |
| `remote_sensor_node_uninstall.py` | Remote uninstall orchestration |
| `requirements-node-deploy.txt` | Deployment-only Python dependencies |
| `templates/` | Sensor YAML, systemd, and Apptainer Jinja2 templates |
