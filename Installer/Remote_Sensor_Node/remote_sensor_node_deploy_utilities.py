"""Remote shell scripts used by the sensor-node deployer."""

from pathlib import Path


APPTAINER_INSTALLER = (
    Path(__file__).resolve().parent.parent / "install_apptainer_package.sh"
)


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

    INSTALL_APPTAINER_SCRIPT = APPTAINER_INSTALLER.read_text(encoding="utf-8")

    INSTALL_SCRIPT = """\
set -eu
stage=$1; root=$2; release_id=$3; service=$4
user=$5; group=$6; apptainer=$7
release="$root/releases/$release_id"; state="$root/state"
runtime="$state/runtime"; sensor_data="$runtime/sensor-node"
source_root="$state/source"; source_tree="$source_root/fissure"
trap 'rm -rf -- "$stage"' EXIT
as_service() {
  if [ "$user" = root ]; then "$@"; else runuser -u "$user" -- "$@"; fi
}
seed_runtime_directory() {
  target=$1; source=$2
  test -z "$(find "$target" -mindepth 1 -maxdepth 1 -print -quit)" || return 0
  if [ -f "$state/runtime-overlay.img" ]; then
    as_service "$apptainer" exec --cleanenv \
      --overlay "$state/runtime-overlay.img" --bind "$target:/mnt" \
      "$release/fissure-sensor-node.sif" \
      sh -eu -c 'test ! -d "$1" || cp -R "$1"/. /mnt/' sh "$source"
  else
    as_service "$apptainer" exec --cleanenv --bind "$target:/mnt" \
      "$release/fissure-sensor-node.sif" \
      sh -eu -c 'test ! -d "$1" || cp -R "$1"/. /mnt/' sh "$source"
  fi
}
install -d -m 0755 "$root" "$root/releases"
install -d -o "$user" -g "$group" -m 0700 \
  "$release" "$release/certificates" "$release/certificates/clients" \
  "$release/certificates/server" "$state" "$state/home" "$state/logs" \
  "$source_root" "$source_tree" "$runtime" \
  "$runtime/plugins" "$runtime/flow-graphs" \
  "$runtime/artifacts" "$runtime/artifacts-node" "$runtime/artifacts-system" \
  "$runtime/archive" \
  "$runtime/iq-recordings" "$runtime/plugin-logs" "$sensor_data" \
  "$sensor_data/archive-replay" "$sensor_data/autorun-playlists" \
  "$sensor_data/iq-data-playback" "$sensor_data/import-export" \
  "$sensor_data/recordings"
install -o "$user" -g "$group" -m 0444 \
  "$stage/fissure-sensor-node.sif" "$release/fissure-sensor-node.sif"
install -o "$user" -g "$group" -m 0440 \
  "$stage/default.yaml" "$release/default.yaml"
install -o "$user" -g "$group" -m 0400 \
  "$stage/client_0.key_secret" "$release/certificates/clients/client_0.key_secret"
install -o "$user" -g "$group" -m 0444 \
  "$stage/server.key" "$release/certificates/server/server.key"
seed_runtime_directory "$source_tree" /opt/FISSURE/fissure
test -f "$source_tree/Sensor_Node/SensorNode.py" || {
  echo "Sensor Node source is missing from the image" >&2
  exit 43
}
seed_runtime_directory "$runtime/plugins" /opt/FISSURE/Plugins
seed_runtime_directory "$runtime/flow-graphs" '/opt/FISSURE/Flow Graph Library'
seed_runtime_directory "$runtime/archive" /opt/FISSURE/Archive
seed_runtime_directory "$runtime/iq-recordings" '/opt/FISSURE/IQ Recordings'
seed_runtime_directory "$runtime/plugin-logs" /opt/FISSURE/logs
seed_runtime_directory "$runtime/artifacts" /opt/FISSURE/artifacts
seed_runtime_directory "$runtime/artifacts-node" /opt/FISSURE/artifacts_node
seed_runtime_directory "$runtime/artifacts-system" /opt/FISSURE/artifacts_system
seed_runtime_directory "$sensor_data/archive-replay" \
  /opt/FISSURE/fissure/Sensor_Node/Archive_Replay
seed_runtime_directory "$sensor_data/autorun-playlists" \
  /opt/FISSURE/fissure/Sensor_Node/Autorun_Playlists
seed_runtime_directory "$sensor_data/iq-data-playback" \
  /opt/FISSURE/fissure/Sensor_Node/IQ_Data_Playback
seed_runtime_directory "$sensor_data/import-export" \
  /opt/FISSURE/fissure/Sensor_Node/Import_Export_Files
seed_runtime_directory "$sensor_data/recordings" \
  /opt/FISSURE/fissure/Sensor_Node/Recordings
# This stable in-image path also exists in SIFs built before the source move.
as_service "$apptainer" exec --cleanenv \
  --home "$state/home:/home/fissure" \
  --bind "$release/default.yaml:/opt/FISSURE/YAML/Sensor_Node_Config/default.yaml:ro" \
  --bind "$release/certificates:/opt/FISSURE/certificates:ro" \
  "$release/fissure-sensor-node.sif" \
  python3 /opt/FISSURE/Installer/remote_sensor_node_image_check.py
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

    RESTART_SERVICE_SCRIPT = """\
set -eu
root=$1; service=$2
test -d "$root/current" || { echo "No active sensor-node installation" >&2; exit 30; }
systemctl cat "$service.service" >/dev/null || {
  echo "Sensor-node service is not installed" >&2
  exit 32
}
systemctl restart "$service.service"
"""

    CLEAR_DATA_SCRIPT = """\
set -eu
root=$1; service=$2; data_kind=$3
runtime="$root/state/runtime"; sensor_data="$runtime/sensor-node"
test -d "$root/current" || { echo "No active sensor-node installation" >&2; exit 30; }
systemctl cat "$service.service" >/dev/null || {
  echo "Sensor-node service is not installed" >&2
  exit 32
}
case "$data_kind" in
  logs)
    targets=("$root/state/logs" "$runtime/plugin-logs")
    ;;
  artifacts)
    targets=(
      "$runtime/artifacts"
      "$runtime/artifacts-node"
      "$runtime/artifacts-system"
    )
    ;;
  recordings)
    targets=(
      "$runtime/archive"
      "$runtime/iq-recordings"
      "$sensor_data/archive-replay"
      "$sensor_data/recordings"
    )
    ;;
  *)
    echo "Unsupported data category: $data_kind" >&2
    exit 34
    ;;
esac
for directory in "${targets[@]}"; do
  test -d "$directory" || { echo "Data directory is missing: $directory" >&2; exit 35; }
done
service_stopped=false
restart_if_stopped() {
  if [ "$service_stopped" = true ]; then systemctl start "$service.service"; fi
}
# Bring the service back if cleanup fails after it has stopped.
trap restart_if_stopped EXIT
systemctl stop "$service.service"
service_stopped=true
for directory in "${targets[@]}"; do
  # Do not cross a filesystem mounted below a data directory.
  find "$directory" -mindepth 1 -xdev -delete
done
systemctl start "$service.service"
service_stopped=false
trap - EXIT
"""

    SYNC_PLUGINS_SCRIPT = """\
set -eu
stage=$1; root=$2; service=$3; user=$4; group=$5
archive="$stage/plugins.tar"; source="$stage/plugins"
target="$root/state/runtime/plugins"
service_stopped=false
finish() {
  status=$?
  trap - EXIT
  if [ "$service_stopped" = true ]; then
    systemctl start "$service.service" || status=$?
  fi
  rm -rf -- "$stage" || true
  exit "$status"
}
# Restart the service if applying the archive fails after it has stopped.
trap finish EXIT
test -d "$root/current" || { echo "No active sensor-node installation" >&2; exit 30; }
test -f "$archive" || { echo "Plugin archive is missing" >&2; exit 36; }
test -d "$target" && test ! -L "$target" || {
  echo "Plugin directory is missing or unsafe: $target" >&2
  exit 37
}
systemctl cat "$service.service" >/dev/null || {
  echo "Sensor-node service is not installed" >&2
  exit 32
}
mkdir -m 0700 "$source"
tar -xf "$archive" -C "$source"
systemctl stop "$service.service"
service_stopped=true
# Merge local files into the host directory; remote-only plugins remain in place.
cp -a --remove-destination "$source"/. "$target"/
find "$target" -type d -name __pycache__ -prune -exec rm -rf -- {} +
find "$target" -type f \\( -name '*.pyc' -o -name '*.pyo' \\) -delete
chown -R "$user:$group" "$target"
systemctl start "$service.service"
service_stopped=false
"""

    SYNC_SOURCE_SCRIPT = """\
set -eu
stage=$1; root=$2; service=$3; user=$4; group=$5
unit_dir=${6:-/etc/systemd/system}
archive="$stage/source.tar"; source="$stage/source"
source_root="$root/state/source"; target="$source_root/fissure"
unit="$stage/$service.service"
service_stopped=false
finish() {
  status=$?
  trap - EXIT
  if [ "$service_stopped" = true ]; then
    systemctl start "$service.service" || status=$?
  fi
  rm -rf -- "$stage" || true
  exit "$status"
}
# Keep the existing service available if applying source or its unit fails.
trap finish EXIT
test -d "$root/current" || { echo "No active sensor-node installation" >&2; exit 30; }
test -f "$archive" || { echo "Source archive is missing" >&2; exit 38; }
test -f "$unit" || { echo "Updated service unit is missing" >&2; exit 39; }
if [ -e "$source_root" ]; then
  test -d "$source_root" && test ! -L "$source_root" || {
    echo "Source root is unsafe: $source_root" >&2
    exit 40
  }
else
  install -d -o "$user" -g "$group" -m 0700 "$source_root"
fi
if [ -e "$target" ]; then
  test -d "$target" && test ! -L "$target" || {
    echo "Source directory is unsafe: $target" >&2
    exit 41
  }
else
  install -d -o "$user" -g "$group" -m 0700 "$target"
fi
systemctl cat "$service.service" >/dev/null || {
  echo "Sensor-node service is not installed" >&2
  exit 32
}
mkdir -m 0700 "$source"
tar -xf "$archive" -C "$source"
systemctl stop "$service.service"
service_stopped=true
# Merge source explicitly; files that exist only on the node remain in place.
cp -a --remove-destination "$source"/. "$target"/
test -f "$target/Sensor_Node/SensorNode.py" || {
  echo "Synchronized Sensor Node source is missing" >&2
  exit 43
}
find "$target" -type d -name __pycache__ -prune -exec rm -rf -- {} +
find "$target" -type f \\( -name '*.pyc' -o -name '*.pyo' \\) -delete
# Nested bind targets must not redirect root-owned setup outside the source tree.
for runtime_dir in \
  Archive_Replay Autorun_Playlists IQ_Data_Playback \
  Import_Export_Files Recordings; do
  test ! -L "$target/Sensor_Node/$runtime_dir" || {
    echo "Source runtime directory is unsafe: $runtime_dir" >&2
    exit 42
  }
done
install -d -o "$user" -g "$group" -m 0700 \
  "$target/Sensor_Node/Archive_Replay" \
  "$target/Sensor_Node/Autorun_Playlists" \
  "$target/Sensor_Node/IQ_Data_Playback" \
  "$target/Sensor_Node/Import_Export_Files" \
  "$target/Sensor_Node/Recordings"
chown -R -h "$user:$group" "$target"
install -m 0644 "$unit" "$unit_dir/$service.service"
systemctl daemon-reload
systemctl start "$service.service"
service_stopped=false
"""

    UPDATE_IMAGE_SCRIPT = """\
set -eu
stage=$1; root=$2; service=$3
image="$root/current/fissure-sensor-node.sif"
candidate="$image.new"
trap 'rm -rf -- "$stage"; rm -f -- "$candidate"' EXIT
test -d "$root/current" || { echo "No active sensor-node installation" >&2; exit 30; }
test -f "$image" || { echo "Active sensor-node SIF is missing" >&2; exit 33; }
systemctl cat "$service.service" >/dev/null || {
  echo "Sensor-node service is not installed" >&2
  exit 32
}
# Rename only after the complete upload is installed, so a running process
# continues using the old inode until systemd deliberately restarts it.
install -m 0444 "$stage/fissure-sensor-node.sif" "$candidate"
chown --reference="$image" "$candidate"
mv -f -- "$candidate" "$image"
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
