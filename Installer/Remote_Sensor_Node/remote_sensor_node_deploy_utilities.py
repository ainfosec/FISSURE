"""Remote shell scripts used by the sensor-node deployer."""


class DeploymentUtilities:
    """Shell scripts executed on the remote sensor node."""

    PREFLIGHT_SCRIPT = """\
set -eu
command -v systemctl >/dev/null || { echo "systemd is unavailable" >&2; exit 11; }
test -d /run/udev || { echo "/run/udev is unavailable" >&2; exit 13; }
if [ "$(id -u)" -eq 0 ]; then
  privilege=root
else
  command -v sudo >/dev/null || { echo "sudo is required" >&2; exit 12; }
  command -v runuser >/dev/null || { echo "runuser is required" >&2; exit 14; }
  if sudo -n true >/dev/null 2>&1; then
    privilege=passwordless
  else
    privilege=password
  fi
fi
printf '%s|%s|%s|%s\\n' \
  "$(id -un)" "$(id -gn)" "$(command -v apptainer || true)" "$privilege"
"""

    UNINSTALL_PREFLIGHT_SCRIPT = """\
set -eu
command -v systemctl >/dev/null || { echo "systemd is unavailable" >&2; exit 11; }
if [ "$(id -u)" -eq 0 ]; then
  privilege=root
else
  command -v sudo >/dev/null || { echo "sudo is required" >&2; exit 12; }
  if sudo -n true >/dev/null 2>&1; then
    privilege=passwordless
  else
    privilege=password
  fi
fi
printf '%s\\n' "$privilege"
"""

    INSTALL_APPTAINER_SCRIPT = """\
set -eu
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
  *" ubuntu "*) ;;
  *)
    echo "Automatic Apptainer installation supports Ubuntu-derived systems only" >&2
    exit 20
    ;;
esac
architecture=$(dpkg --print-architecture)
case "$architecture" in
  amd64|arm64) ;;
  *)
    echo "Automatic Apptainer installation does not support $architecture" >&2
    exit 21
    ;;
esac
# The signed Apptainer PPA tracks supported Ubuntu releases and architectures.
apt-get update
env DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common
add-apt-repository -y ppa:apptainer/ppa
apt-get update
env DEBIAN_FRONTEND=noninteractive apt-get install -y apptainer
apptainer version >/dev/null
"""

    INSTALL_SCRIPT = """\
set -eu
stage=$1; root=$2; release_id=$3; service=$4
user=$5; group=$6; apptainer=$7; overlay_size=$8
release="$root/releases/$release_id"; state="$root/state"
trap 'rm -rf -- "$stage"' EXIT
as_service() {
  if [ "$user" = root ]; then "$@"; else runuser -u "$user" -- "$@"; fi
}
install -d -m 0755 "$root" "$root/releases"
install -d -o "$user" -g "$group" -m 0700 \
  "$release" "$release/certificates" "$release/certificates/clients" \
  "$release/certificates/server" "$state" "$state/home" "$state/logs"
install -o "$user" -g "$group" -m 0444 \
  "$stage/fissure-sensor-node.sif" "$release/fissure-sensor-node.sif"
install -o "$user" -g "$group" -m 0440 \
  "$stage/default.yaml" "$release/default.yaml"
install -o "$user" -g "$group" -m 0400 \
  "$stage/client_0.key_secret" "$release/certificates/clients/client_0.key_secret"
install -o "$user" -g "$group" -m 0444 \
  "$stage/server.key" "$release/certificates/server/server.key"
# This stable in-image path also exists in SIFs built before the source move.
as_service "$apptainer" exec --cleanenv \
  --home "$state/home:/home/fissure" \
  --bind "$release/default.yaml:/opt/FISSURE/YAML/Sensor_Node_Config/default.yaml:ro" \
  --bind "$release/certificates:/opt/FISSURE/certificates:ro" \
  "$release/fissure-sensor-node.sif" \
  python3 /opt/FISSURE/Installer/remote_sensor_node_image_check.py
if [ ! -f "$state/runtime-overlay.img" ]; then
  as_service "$apptainer" overlay create \
    --size "$overlay_size" "$state/runtime-overlay.img"
  chmod 0600 "$state/runtime-overlay.img"
fi
install -o root -g root -m 0644 \
  "$stage/$service.service" "/etc/systemd/system/$service.service"
systemctl stop "$service.service" >/dev/null 2>&1 || true
link="$root/current.$release_id"
ln -s "$release" "$link"
mv -Tf "$link" "$root/current"
systemctl daemon-reload
systemctl enable "$service.service" >/dev/null
systemctl start "$service.service"
"""

    UPDATE_CONFIG_SCRIPT = """\
set -eu
stage=$1; root=$2; service=$3
config="$root/current/default.yaml"
candidate="$config.new"
trap 'rm -rf -- "$stage"; rm -f -- "$candidate"' EXIT
test -d "$root/current" || { echo "No active sensor-node installation" >&2; exit 30; }
test -f "$config" || { echo "Active sensor-node config is missing" >&2; exit 31; }
systemctl cat "$service.service" >/dev/null || {
  echo "Sensor-node service is not installed" >&2
  exit 32
}
install -m 0440 "$stage/default.yaml" "$candidate"
chown --reference="$config" "$candidate"
mv -f -- "$candidate" "$config"
systemctl restart "$service.service"
"""

    UNINSTALL_SCRIPT = """\
set -eu
root=$1; service=$2
unit="/etc/systemd/system/$service.service"
systemctl disable --now "$service.service" >/dev/null 2>&1 || true
rm -f -- "$unit"
systemctl daemon-reload
systemctl reset-failed "$service.service" >/dev/null 2>&1 || true
rm -rf --one-file-system -- "$root"
"""
