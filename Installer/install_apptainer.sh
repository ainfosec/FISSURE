#!/bin/bash
set -e

#############################################
#          FISSURE Apptainer Installer      #
#############################################
# Example usage:
#   ./install_apptainer.sh \
#       --host-os "Ubuntu 24.04" \
#       --apptainer-os "Ubuntu 24.04" \
#       --mode base \
#       --build-apptainer \
#       --install-host-deps \
#       --install-fissure-cmd \
#       --db --meshtastic --uhd --hackrf --wifi --usrp-x300 --iqengine --takserver
#
# Common modes:
#   full       - Includes every installer item enabled by default
#   base       - Core FISSURE dependencies and shared components
#   custom     - Uses the installer items listed in Modes/custom.py
#   Dashboard  - Dashboard-focused installation
#   HIPRFISR   - HIPRFISR-focused installation
#   SensorNode - Sensor Node-focused installation
#############################################

# Detect where the script lives (Installer) and use its parent as the host FISSURE directory
SCRIPT_PATH="$(realpath "$0")"
INSTALLER_DIR="$(dirname "$SCRIPT_PATH")"
HOST_FISSURE_DIR="$(dirname "$INSTALLER_DIR")"
SANDBOX_DIR="$HOME/fissure_apptainer"
DEF_FILE="$INSTALLER_DIR/fissure_apptainer.def"

# Default paths and settings
APPTAINER_FISSURE_DIR="/opt/FISSURE"
HOST_OS="Ubuntu 24.04"
APPTAINER_OS="Ubuntu 24.04"
MODE="full"
BUILD_APPTAINER=true
INSTALL_HOST_DEPS=true
INSTALL_FISSURE_CMD=true
DB=true 
AUTO_LAUNCH_SENSOR_NODE=false
MESHTASTIC=true
UHD=true
RTLSDR=true
HACKRF=true
WIFI=true
USRP_X300=true
IQENGINE=true
TAKSERVER=false


#############################################
#              Parse arguments              #
#############################################
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --host-os) HOST_OS="$2"; shift ;;
        --apptainer-os) APPTAINER_OS="$2"; shift ;;
        --mode) MODE="$2"; shift ;;
        --build-apptainer) BUILD_APPTAINER=true ;;
        --install-host-deps) INSTALL_HOST_DEPS=true ;;
        --install-fissure-cmd) INSTALL_FISSURE_CMD=true ;;
        --auto-launch-sensor-node)
            AUTO_LAUNCH_SENSOR_NODE=true ;;
        --db) DB=true ;;
        --meshtastic) MESHTASTIC=true ;;
        --uhd) UHD=true ;;
        --rtlsdr) RTLSDR=true ;;
        --hackrf) HACKRF=true ;;
        --wifi) WIFI=true ;;
        --usrp-x300)
            USRP_X300=true ;;
        --iqengine) IQENGINE=true ;;
        --takserver) TAKSERVER=true ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo
            echo "Options:"
            echo "  --host-os 'Ubuntu 24.04'       Host operating system label"
            echo "  --apptainer-os 'Ubuntu 24.04'  Apptainer container OS base"
            echo "  --mode MODE                    full, base, custom, Dashboard, HIPRFISR, or SensorNode"
            echo "  --build-apptainer              Build the writable Apptainer sandbox"
            echo "  --install-host-deps            Install host dependencies (drivers, Docker, etc.)"
            echo "  --auto-launch-sensor-node      Launch the Apptainer Sensor Node after graphical login"
            echo "  --db                           Configure PostgreSQL host environment"
            echo "  --meshtastic                   Configure Meshtastic host environment"
            echo "  --uhd                          Configure UHD (USRP) host drivers"
            echo "  --rtlsdr                       Configure RTL-SDR host setup"
            echo "  --hackrf                       Configure HackRF host drivers"
            echo "  --wifi                         Configure Wi-Fi capture host setup"
            echo "  --usrp-x300                    Configure USRP X300 Series host setup"
            echo "  --iqengine                     Configure IQ Engine Docker setup"
            echo "  --takserver                    Configure local TAK Server Docker setup"
            echo "  -h, --help                     Show this help message and exit"
            exit 0 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
    shift
done

#############################################
#       Validate and normalize mode         #
#############################################
case "${MODE,,}" in
    full)
        MODE="full"
        ;;
    base)
        MODE="base"
        ;;
    custom)
        MODE="custom"
        ;;
    dashboard)
        MODE="Dashboard"
        ;;
    hiprfisr)
        MODE="HIPRFISR"
        ;;
    sensor|sensor-node|sensor_node|sensornode)
        MODE="SensorNode"
        ;;
    *)
        echo "[ERROR] Unsupported install mode: $MODE"
        echo "        Supported modes: full, base, custom, Dashboard, HIPRFISR, SensorNode"
        exit 1
        ;;
esac

echo "[*] FISSURE install mode: $MODE"

#############################################
# Verify FISSURE repo location
#############################################
if [ ! -d "$HOST_FISSURE_DIR/fissure" ]; then
    echo "[!] Could not find FISSURE source in $HOST_FISSURE_DIR"
    echo "    Please clone the repository first:"
    echo "    sudo git clone https://github.com/ainfosec/FISSURE.git /opt/FISSURE"
    exit 1
fi

echo "[*] Host FISSURE directory: $HOST_FISSURE_DIR"
echo "[*] Apptainer FISSURE directory: $APPTAINER_FISSURE_DIR"

#############################################
# Install Apptainer Software
#############################################
install_apptainer_suid() {
    echo "[*] Installing Apptainer with setuid support..."

    sudo apt update
    sudo apt install -y software-properties-common

    if ! grep -Rqs "ppa.launchpadcontent.net/apptainer/ppa" \
        /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
        sudo add-apt-repository -y ppa:apptainer/ppa
    fi

    sudo apt update
    sudo apt install -y apptainer-suid
}

if ! command -v apptainer >/dev/null 2>&1; then
    install_apptainer_suid
elif ! apptainer buildcfg 2>/dev/null |
       grep -q '^APPTAINER_SUID_INSTALL=1$'; then
    echo "[!] Existing Apptainer installation does not have setuid support."
    install_apptainer_suid
else
    echo "[✓] Existing Apptainer installation has setuid support."
fi

if ! command -v apptainer >/dev/null 2>&1; then
    echo "[ERROR] Apptainer installation failed."
    exit 1
fi

if ! apptainer buildcfg 2>/dev/null |
     grep -q '^APPTAINER_SUID_INSTALL=1$'; then
    echo "[ERROR] Apptainer is installed without required setuid support."
    exit 1
fi

echo "[✓] $(apptainer version)"

#############################################
#          Host Preparation (optional)      #
#############################################
if $INSTALL_HOST_DEPS; then
    echo "[*] Preparing host environment for FISSURE on $HOST_OS..."

    # Check and Install pip3
    if command -v pip3 >/dev/null 2>&1; then
        echo "[✓] pip3 is already installed."
    else
        echo "[*] pip3 not found — installing..."
        sudo apt-get update
        sudo apt-get install -y python3-pip
        if command -v pip3 >/dev/null 2>&1; then
            echo "[✓] pip3 installed successfully."
        else
            echo "[!] pip3 installation failed. Please check your package sources."
        fi
    fi

    if [[ "$HOST_OS" == "Ubuntu 24.04" ]]; then
        # ---------- Auto-Launch Sensor Node ----------
        if $AUTO_LAUNCH_SENSOR_NODE; then
            echo "[*] Configuring Apptainer Sensor Node launcher and autostart on host..."

            mkdir -p "$HOME/.local/bin"
            mkdir -p "$HOME/.config/autostart"

            SENSOR_NODE_LAUNCHER="$HOME/.local/bin/fissure-apptainer-sensor-node"

            cat <<EOF > "$SENSOR_NODE_LAUNCHER"
#!/bin/bash
set -e

HOST_FISSURE_DIR="$HOST_FISSURE_DIR"
APPTAINER_FISSURE_DIR="$APPTAINER_FISSURE_DIR"
SIF_IMAGE="\$HOME/fissure_apptainer.sif"
SANDBOX_IMAGE="\$HOME/fissure_apptainer"

if [ -f "\$SIF_IMAGE" ]; then
    APPTAINER_IMAGE="\$SIF_IMAGE"
elif [ -d "\$SANDBOX_IMAGE" ]; then
    APPTAINER_IMAGE="\$SANDBOX_IMAGE"
else
    echo "[ERROR] No FISSURE Apptainer image was found."
    echo "        Expected either:"
    echo "          \$SIF_IMAGE"
    echo "          \$SANDBOX_IMAGE"
    exit 1
fi

if [ ! -d "\$HOST_FISSURE_DIR/fissure" ]; then
    echo "[ERROR] FISSURE source was not found at \$HOST_FISSURE_DIR"
    exit 1
fi

APPTAINER_ARGS=(
    exec
    --bind "\$HOST_FISSURE_DIR:\$APPTAINER_FISSURE_DIR"
    --env "PYTHONPATH=\$APPTAINER_FISSURE_DIR"
)

if [ -d /dev/bus/usb ]; then
    APPTAINER_ARGS+=(--bind /dev/bus/usb:/dev/bus/usb)
fi

if [ -d /run/udev ]; then
    APPTAINER_ARGS+=(--bind /run/udev:/run/udev)
fi

for dev in /dev/ttyACM* /dev/ttyUSB*; do
    if [ -e "\$dev" ]; then
        APPTAINER_ARGS+=(--bind "\$dev:\$dev")
    fi
done

exec apptainer "\${APPTAINER_ARGS[@]}" \
    "\$APPTAINER_IMAGE" \
    fissure-sensor-node
EOF

            chmod +x "$SENSOR_NODE_LAUNCHER"

            cat <<EOF > "$HOME/.config/autostart/fissure-sensor-node.desktop"
[Desktop Entry]
Type=Application
Terminal=true
Name=FISSURE Sensor Node
Comment=Launch the FISSURE Sensor Node through Apptainer
Exec=gnome-terminal -- bash -c 'sleep 1; "$HOME/.local/bin/fissure-apptainer-sensor-node"; exec bash'
X-GNOME-Autostart-enabled=true
EOF

            chmod +x "$HOME/.config/autostart/fissure-sensor-node.desktop"

            echo "[✓] Apptainer Sensor Node launcher installed at: $SENSOR_NODE_LAUNCHER"
            echo "[✓] Sensor Node autostart configured at: $HOME/.config/autostart/fissure-sensor-node.desktop"
            echo "[i] Sensor Node autostart runs when the host desktop session starts."
        fi
        # ---------- End Auto-Launch Sensor Node ----------

        # ---------- Meshtastic Host Setup ----------
        if $MESHTASTIC; then
            echo "[*] Installing Meshtastic host dependencies..."
            sudo apt-get update
            sudo apt-get install -y python3-serial
            sudo apt-get install -y python3-protobuf

            echo "[*] Installing Meshtastic Python package..."
            sudo python3 -m pip install "meshtastic==2.6.4" --break-system-packages

            echo "[*] Applying Meshtastic udev and permission rules..."
            # Add user to necessary serial groups
            sudo usermod -aG dialout "$USER"
            sudo usermod -aG tty "$USER"

            # Add udev rule for Meshtastic devices (Silicon Labs CP210x)
            echo 'SUBSYSTEM=="tty", ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="ea60", MODE="0666"' | \
                sudo tee /etc/udev/rules.d/99-meshtastic.rules > /dev/null

            sudo udevadm control --reload-rules
            sudo udevadm trigger

            echo "[✓] Meshtastic host configuration complete."
        fi
        # ---------- End Meshtastic Host Setup ----------

        # ---------- PostgreSQL Host Setup ----------
        if $DB; then
            echo "[*] Installing PostgreSQL host dependencies and Docker components..."
            sudo apt-get update
            sudo apt-get install -y docker.io docker-compose-v2 postgresql-client libpq-dev python3-pip
            sudo python3 -m pip install python-dotenv psycopg2 --break-system-packages
            sudo usermod -aG docker ${USER}

            echo "[*] Ensuring example.env exists and starting PostgreSQL container..."
            cd "$HOST_FISSURE_DIR"
            if [ ! -f .env ]; then
                cp example.env .env
            fi

            bash -c '
                set -e
                set -o allexport
                source .env
                set +o allexport
                export PGPASSWORD=$POSTGRES_PASSWORD
                echo "[*] Starting PostgreSQL container..."
                sudo docker compose up -d
                until pg_isready -U "$POSTGRES_USER" -h "$POSTGRES_HOST" -p "$POSTGRES_EXTERNAL_PORT"; do
                    echo "Waiting for PostgreSQL to be ready..."
                    sleep 2
                done
                echo "[*] Restoring FISSURE database..."
                pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" -h "$POSTGRES_HOST" -p "$POSTGRES_EXTERNAL_PORT" -v db/fissure_db_dump.sql
                echo "[*] Verifying connection..."
                psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -h "$POSTGRES_HOST" -p "$POSTGRES_EXTERNAL_PORT" \
                     -c "SELECT COUNT(*) FROM pg_tables;"
            '

            echo "[✓] PostgreSQL host setup complete."
        fi
        # ---------- End PostgreSQL Host Setup ----------

        # ---------- UHD Host Setup ----------
        if $UHD; then
            echo "[*] Installing UHD host dependencies and configuring USB access..."
            sudo apt-get update
            sudo apt-get install -y uhd-host

            # Copy udev rule if present
            if [ -f /usr/lib/uhd/utils/uhd-usrp.rules ]; then
                sudo cp /usr/lib/uhd/utils/uhd-usrp.rules /etc/udev/rules.d/
            elif [ -f /usr/share/uhd/utils/uhd-usrp.rules ]; then
                sudo cp /usr/share/uhd/utils/uhd-usrp.rules /etc/udev/rules.d/
            else
                echo "[!] UHD udev rule not found — continuing anyway."
            fi

            # Reload udev rules
            sudo udevadm control --reload-rules
            sudo udevadm trigger

            # Ensure plugdev group exists and user has access
            if ! getent group plugdev >/dev/null; then
                sudo groupadd plugdev
            fi
            HOST_USER="${SUDO_USER:-$USER}"
            sudo usermod -aG plugdev "$HOST_USER"

            echo "[*] Downloading UHD FPGA images..."
            sudo mkdir -p /usr/share/uhd
            sudo chmod -R 777 /usr/share/uhd
            uhd_images_downloader || echo "[!] UHD image download failed (check network)."

            echo "[✓] UHD host configuration complete."
        fi
        # ---------- End UHD Host Setup ----------
        
        # ---------- RTL-SDR Host Setup ----------
        if $RTLSDR; then
            echo "[*] Setting up RTL-SDR host device access..."

            echo 'blacklist dvb_usb_rtl28xxu' \
                | sudo tee /etc/modprobe.d/rtl-sdr.conf >/dev/null

            sudo rm -f /etc/udev/rules.d/20.rtlsdr.rules

            echo 'SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="2838", MODE:="0666"' \
                | sudo tee /etc/udev/rules.d/99-fissure-rtlsdr.rules >/dev/null

            sudo udevadm control --reload-rules
            sudo udevadm trigger

            echo "[✓] RTL-SDR host device access configured."
            echo "[!] Unplug and reconnect the RTL-SDR. A reboot may be required if the DVB driver is already loaded."
        fi
        # ---------- End RTL-SDR Host Setup ----------

        # ---------- HackRF Host Setup ----------
        if $HACKRF; then
            echo "[*] Installing HackRF host dependencies and udev rules..."
            sudo apt-get update
            sudo apt-get install -y hackrf libhackrf-dev

            # Install udev rule if present in FISSURE Tools
            if [ -f "$HOST_FISSURE_DIR/Tools/53-hackrf.rules" ]; then
                echo "[*] Copying HackRF udev rule to /etc/udev/rules.d/..."
                sudo cp "$HOST_FISSURE_DIR/Tools/53-hackrf.rules" /etc/udev/rules.d/53-hackrf.rules
            else
                echo "[!] HackRF udev rule not found at $HOST_FISSURE_DIR/Tools/53-hackrf.rules"
                echo "    Skipping rule installation (non-critical)."
            fi

            # Reload udev rules
            sudo udevadm control --reload-rules
            sudo udevadm trigger

            # Verify device access and version
            echo "[*] Verifying HackRF installation..."
            if command -v hackrf_info >/dev/null 2>&1; then
                hackrf_info || echo "[!] HackRF device not detected (may not be plugged in)."
            else
                echo "[!] hackrf_info not found — check that hackrf-tools installed correctly."
            fi

            echo "[✓] HackRF host configuration complete."
        fi
        # ---------- End HackRF Host Setup ----------

        # ---------- Wi-Fi Host Setup (rtl8812au via aircrack-ng) ----------
        if $WIFI; then
            echo "[*] Installing Wi-Fi host dependencies and driver (rtl8812au) on host..."

            sudo apt-get update
            sudo apt-get -y install dkms git build-essential

            mkdir -p "$HOME/Installed_by_FISSURE"
            cd "$HOME/Installed_by_FISSURE"

            if [ -d rtl8812au ]; then
                echo "[*] rtl8812au repository already exists — using existing clone."
            else
                git clone https://github.com/aircrack-ng/rtl8812au
            fi

            cd rtl8812au
            sudo make dkms_install

            ########## Verify ##########
            sudo modprobe 8812au && echo "[✓] rtl8812au module loaded successfully" || echo "[!] rtl8812au module load failed"
        fi
        # ---------- End Wi-Fi Host Setup ----------

        # ---------- USRP X300/X310 Host Setup ----------
        if $USRP_X300; then
            echo "[*] Installing USRP X300/X310 host dependencies..."

            # Ensure UHD host tools are available
            if ! dpkg -l | grep -q uhd-host; then
                echo "[*] Installing UHD host package..."
                sudo apt-get update
                sudo apt-get install -y uhd-host
            else
                echo "[✓] UHD host package already installed."
            fi

            # Download UHD FPGA images
            echo "[*] Downloading UHD FPGA images for X300/X310..."
            if [ -x /usr/lib/uhd/utils/uhd_images_downloader.py ]; then
                sudo /usr/lib/uhd/utils/uhd_images_downloader.py
            elif [ -x /usr/bin/uhd_images_downloader ]; then
                sudo /usr/bin/uhd_images_downloader
            else
                echo "[!] UHD image downloader not found after installation."
            fi

            # Increase socket buffer size for high throughput
            echo "[*] Adjusting system network buffers for USRP operation..."
            sudo sysctl -w net.core.wmem_max=24862979 || echo "[!] sysctl update failed (non-critical)."

            echo "[✓] USRP X300/X310 host configuration complete."
        fi
        # ---------- End USRP X300/X310 Host Setup ----------

        # ---------- IQEngine Host Setup ----------
        if $IQENGINE; then
            echo "[*] Installing and preparing IQEngine Docker environment..."

            # Ensure Docker is installed (only docker.io)
            if ! command -v docker > /dev/null 2>&1; then
                echo "[*] Installing Docker..."
                sudo apt-get update
                sudo apt-get install -y docker.io
                sudo usermod -aG docker ${USER}
                echo "[✓] Docker installed. (Reboot may be required for group changes.)"
            else
                echo "[✓] Docker already installed."
            fi

            # Clone IQEngine once
            mkdir -p "$HOME/Installed_by_FISSURE"
            cd "$HOME/Installed_by_FISSURE"

            if [ ! -d IQEngine ]; then
                git clone https://github.com/IQEngine/IQEngine.git
            else
                echo "[!] IQEngine directory already exists — skipping clone."
            fi

            cd "$HOME/Installed_by_FISSURE/IQEngine"
            cp -n example.env .env

            # Pull IQEngine image
            echo "[*] Pulling IQEngine image..."
            sudo docker pull ghcr.io/iqengine/iqengine:pre

            # Verify IQEngine container existence
            echo "[*] Verifying IQEngine container existence..."
            if sudo docker ps -a --filter "ancestor=ghcr.io/iqengine/iqengine:pre" --format '{{.ID}} {{.Status}} {{.Names}}' | grep -q .; then
                echo "[✓] IQEngine container exists (running or stopped)."
            else
                echo "[!] IQEngine container not found on host."
                echo "    You can start one manually with:"
                echo "    sudo docker run --env-file .env -v '$HOST_FISSURE_DIR/IQ Recordings':/tmp/myrecordings -p 3001:3000 -d ghcr.io/iqengine/iqengine:pre"
            fi

            # Quick Docker sanity check
            echo "[*] Running Docker hello-world check..."
            sudo docker run --rm hello-world >/dev/null && echo "[✓] Docker daemon working." || echo "[!] Docker test failed."

            echo "[✓] IQEngine host setup complete."
        fi
        # ---------- End IQEngine Host Setup ----------

        # ---------- TAK Server Setup ----------
        if $TAKSERVER; then
            # Create TAK.gov account and download TAKSERVER-DOCKER-#.#-RELEASE-##.ZIP from https://tak.gov/products/tak-server
            # Place ZIP file in ~/Installed_by_FISSURE folder and then run this installer item!

            if command -v docker > /dev/null 2>&1; then
                echo "Docker is installed."
            else
                echo "Docker is not installed."
                sudo apt-get install -y docker.io
                #sudo systemctl start docker
                #sudo systemctl enable docker
                sudo usermod -aG docker ${USER}  # Reboot computer to use docker commands without sudo
                #newgrp docker
            fi

            mkdir -p ~/Installed_by_FISSURE
            cd ~/Installed_by_FISSURE

            # Unzip and move into the extracted directory
            unzip takserver-docker-*.zip
            if [ -n "$(find . -maxdepth 1 -type d -name 'takserver-docker-*' -print -quit)" ]; then
                cd takserver-docker-*/

                # Ensure CoreConfig.xml exists
                [ ! -f tak/CoreConfig.xml ] && cp tak/CoreConfig.example.xml tak/CoreConfig.xml

                # Set database password
                sed -i 's/password=""/password="atakatak"/' tak/CoreConfig.xml

                # Build and start the database
                sudo docker build -t takserver-db:"$(cat tak/version.txt)" -f docker/Dockerfile.takserver-db .
                sudo docker network create takserver-"$(cat tak/version.txt)"

                # Set executable permissions for necessary scripts
                chmod +x tak/db-utils/configureInDocker.sh
                chmod +x tak/certs/makeRootCa.sh
                chmod +x tak/certs/makeCert.sh

                sudo docker run -d \
                    -v $(pwd)/tak:/opt/tak:z \
                    -p 5432:5432 \
                    --network takserver-"$(cat tak/version.txt)" \
                    --network-alias tak-database \
                    --name takserver-db-"$(cat tak/version.txt)" \
                    takserver-db:"$(cat tak/version.txt)"

                # Wait for the database to be fully ready
                echo "Waiting for PostgreSQL to be ready..."
                until sudo docker exec takserver-db-"$(cat tak/version.txt)" psql -U martiuser -d cot -c "SELECT 1;" &>/dev/null; do
                    sleep 3
                    echo "Waiting for database..."
                done
                echo "Database is ready!"

                # Build and start TAK Server
                sudo docker build -t takserver:"$(cat tak/version.txt)" -f docker/Dockerfile.takserver .
                sudo docker run -d \
                    -v $(pwd)/tak:/opt/tak:z \
                    -p 8089:8089 -p 8443:8443 -p 8444:8444 -p 8446:8446 -p 9000:9000 -p 9001:9001 \
                    --network takserver-"$(cat tak/version.txt)" \
                    --name takserver-"$(cat tak/version.txt)" \
                    takserver:"$(cat tak/version.txt)"

                # Modify certificate metadata
                sed -i 's/^STATE=.*/STATE="test_state"/' tak/certs/cert-metadata.sh
                sed -i 's/^CITY=.*/CITY="test_city"/' tak/certs/cert-metadata.sh
                sed -i 's/^ORGANIZATIONAL_UNIT=.*/ORGANIZATIONAL_UNIT="test_organization"/' tak/certs/cert-metadata.sh
                sed -i 's/^ORGANIZATION=.*/ORGANIZATION="test_org"/' tak/certs/cert-metadata.sh

                # Generate Root CA
                sudo docker exec takserver-"$(cat tak/version.txt)" bash -c "cd /opt/tak/certs && ./makeRootCa.sh"

                # Ensure CA certificate exists before continuing
                sudo docker exec takserver-"$(cat tak/version.txt)" bash -c "test -f /opt/tak/certs/files/ca.pem || (echo 'CA generation failed!' && exit 1)"

                # Generate Certificates
                sudo docker exec takserver-"$(cat tak/version.txt)" bash -c "cd /opt/tak/certs && ./makeCert.sh server takserver"
                sudo docker exec takserver-"$(cat tak/version.txt)" bash -c "cd /opt/tak/certs && ./makeCert.sh client admin"
                sudo docker exec takserver-"$(cat tak/version.txt)" bash -c "cd /opt/tak/certs && ./makeCert.sh client webadmin"

                # Ensure directories have correct permissions
                sudo find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -type d -exec chmod 755 {} +
                    
                sudo openssl rsa -in "$(find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -name 'takserver.key' | head -n 1)" \
                    -out "$(find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -type d | head -n 1)/takserver.key.unencrypted" \
                    -passin pass:"atakatak"

                sudo mv "$(ls -d ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files | head -n 1)/takserver.key.unencrypted" \
                    "$(ls -d ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files | head -n 1)/takserver.key"

                # Set ownership for all certificate-related files to the current user
                sudo find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -type f -exec chown $USER:$USER {} +
                sudo find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -type d -exec chown $USER:$USER {} +

                # Set proper permissions for private keys
                sudo find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -type f -name "*.key" -exec chmod 644 {} +

                # Set correct permissions for other certificate files
                sudo find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -type f -not -name "*.key" -exec chmod 644 {} +

                # Restart TAK Server to apply changes
                sudo docker restart takserver-"$(cat tak/version.txt)"

                # Copy takserver.key and takserver.pem to FISSURE Config Files
                cd """ + fissure_directory + """
                PYTHONPATH=""" + fissure_directory + """ python3 fissure/utils/tak_yaml_key_insert.py \
                "$(find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -name 'takserver.key' | head -n 1)" \
                "$(find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -name 'takserver.pem' | head -n 1)" \
                "$(find ~/Installed_by_FISSURE/takserver-docker-*/tak/certs/files/ -name 'webadmin.p12' | head -n 1)" \
                "$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' takserver-5.3-RELEASE-24)"
                
                # Install pytak library
                python3 -m pip install pytak --break-system-packages
                
                # Import webadmin.p12:

                # Google Chrome/Edge
                # Open chrome://settings/certificates in your browser.
                # Go to the "Your certificates" tab.
                # Click "Import".
                # Select /home/cups-pk-helper/webadmin.p12.
                # Enter the password (default: atakatak, unless changed).
                # Complete the import and restart your browser.

                # Mozilla Firefox
                # Open about:preferences#privacy in the Firefox address bar.
                # Scroll down to Certificates and click "View Certificates".
                # Go to the "Your Certificates" tab.
                # Click "Import".
                # Select /home/cups-pk-helper/webadmin.p12 and enter the password (atakatak).
                # Restart Firefox.

                # To Remove TAK:
                # docker ps -a | grep takserver
                # docker rm -f $(docker ps -aq --filter "name=takserver")
                # docker rm -f $(docker ps -aq --filter "name=takserver-db")
                # docker ps -a
                # docker images | grep takserver
                # docker rmi -f $(docker images -q takserver)
                # docker rmi -f $(docker images -q takserver-db)
                # docker images
                # docker network ls | grep takserver
                # docker network rm $(docker network ls --filter "name=takserver" -q)
                # sudo rm -rf ~/Installed_by_FISSURE/takserver-docker-*/

                echo ""
                echo "TAK Server setup complete! Import webadmin.p12 certificate via browser. Access WebTAK at https://localhost:8443"
                echo ""
            else
                echo "TAK Server zip extraction failed or extracted folder not found. Exiting."
            fi
        fi
        # ---------- End TAK Server Setup ----------


        echo "[✓] Host preparation complete for Ubuntu 24.04."

    else
        echo "[!] Unsupported host OS: $HOST_OS"
    fi
fi

#############################################
#           Build the Apptainer             #
#############################################
if $BUILD_APPTAINER; then
    echo "[*] Building new writable FISSURE Apptainer sandbox for $APPTAINER_OS..."
    echo "[*] Using host source: $HOST_FISSURE_DIR"
    echo "[*] Copying into container destination: $APPTAINER_FISSURE_DIR"

    # Check if DEF_FILE is already defined, if not, set it
    if [ -z "$DEF_FILE" ]; then
        DEF_FILE="$INSTALLER_DIR/fissure_apptainer.def"  # permanent source (now in Installer)
    fi
    DEF_TEMP="$INSTALLER_DIR/fissure_build.def"  # temporary build version

    # Determine base image name based on OS
    case "$APPTAINER_OS" in
        "Ubuntu 22.04")
            BASE_IMAGE="ubuntu:22.04" ;;
        "Ubuntu 24.04")
            BASE_IMAGE="ubuntu:24.04" ;;
        "Parrot 6.1")
            BASE_IMAGE="parrot:6.1" ;;
        *)
            echo "[!] Unsupported Apptainer OS: $APPTAINER_OS"
            exit 1 ;;
    esac

    # Generate temporary definition file with replaced placeholders
    sed \
        -e "s|__BASE_IMAGE__|$BASE_IMAGE|g" \
        -e "s|__OS_LABEL__|$APPTAINER_OS|g" \
        -e "s|__HOST_FISSURE_DIR__|$HOST_FISSURE_DIR|g" \
        -e "s|__INSTALL_MODE__|$MODE|g" \
        "$DEF_FILE" > "$DEF_TEMP"

    echo "[*] Verifying generated FISSURE install mode..."
    grep -n -- "--mode" "$DEF_TEMP"

    # Remove old sandbox if it exists
    if [ -d "$SANDBOX_DIR" ]; then
        echo "[!] Removing old sandbox: $SANDBOX_DIR"
        sudo rm -rf "$SANDBOX_DIR"
    fi

    # Build writable sandbox container
    echo "[*] Running: sudo apptainer build --sandbox $SANDBOX_DIR $DEF_TEMP"
    sudo apptainer build --sandbox "$SANDBOX_DIR" "$DEF_TEMP"

    # Clean up temp def file
    rm -f "$DEF_TEMP"

    echo "[✓] Writable container sandbox created at: $SANDBOX_DIR"
    echo
else
    echo "[!] No build flag provided. Use --build-apptainer to build the image."
fi

#############################################
#     Generate Host Network Certificates    #
#############################################
CERT_DIR="$HOST_FISSURE_DIR/certificates"

if [ ! -f "$CERT_DIR/server/server.key" ] ||
   [ ! -f "$CERT_DIR/server/server.key_secret" ] ||
   [ ! -f "$CERT_DIR/clients/client_0.key" ] ||
   [ ! -f "$CERT_DIR/clients/client_0.key_secret" ]; then

    echo "[*] Generating FISSURE network certificates in the host checkout..."

    apptainer exec \
        --bind "$HOST_FISSURE_DIR:$APPTAINER_FISSURE_DIR" \
        --env PYTHONPATH="$APPTAINER_FISSURE_DIR" \
        "$SANDBOX_DIR" \
        bash -c "
            cd '$APPTAINER_FISSURE_DIR'
            python3 ./fissure/generate_certificates.py
        "

    ########## Verify ##########
    test -f "$CERT_DIR/server/server.key" &&
    test -f "$CERT_DIR/server/server.key_secret" &&
    test -f "$CERT_DIR/clients/client_0.key" &&
    test -f "$CERT_DIR/clients/client_0.key_secret"

    echo "[✓] FISSURE network certificates generated in $CERT_DIR"
else
    echo "[✓] Existing FISSURE network certificates found in $CERT_DIR"
fi

#############################################
#        Install fissure-apptainer Cmd       #
#############################################
if [[ "$INSTALL_FISSURE_CMD" == true ]]; then
    echo "[*] Preparing fissure-apptainer launcher..."

    DEST_PATH="$HOME/.local/bin"
    SRC_FILE="$INSTALLER_DIR/fissure-apptainer.sh"
    DEST_FILE="$DEST_PATH/fissure-apptainer"

    # Ensure bin directory exists
    mkdir -p "$DEST_PATH"

    # Add ~/.local/bin to PATH if missing
    if grep -Fq "~/.local/bin" ~/.bashrc; then
        echo "~/.local/bin already present in ~/.bashrc"
    else
        printf "\n%s\n" 'if [ -d "$HOME/.local/bin" ]; then PATH="$PATH:$HOME/.local/bin"; fi' >> ~/.bashrc
        echo "[+] Added ~/.local/bin to PATH in ~/.bashrc"
    fi

    # Ensure source file exists
    if [[ ! -f "$SRC_FILE" ]]; then
        echo "[!] fissure-apptainer.sh not found in $INSTALLER_DIR"
    else
        cp "$SRC_FILE" "$DEST_FILE"

        # Replace placeholders only in the installed copy
        sed -i "s|__FISSURE_DIR__|$HOST_FISSURE_DIR|g" "$DEST_FILE"
        sed -i "s|__FISSURE_MODE__|$MODE|g" "$DEST_FILE"

        chmod +x "$DEST_FILE"
        echo "[✓] fissure-apptainer command installed at $DEST_FILE"
    fi
fi


echo "[✓] Done."