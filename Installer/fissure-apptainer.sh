#!/bin/bash
set -e

FISSURE_DIR="/home/user/FISSURE"
FISSURE_MODE="full"
CONTAINER_DIR="$HOME/fissure_apptainer"
ENV_FILE="$FISSURE_DIR/.env"
MPL_CONFIG_DIR="$HOME/fissure_apptainer_writable/matplotlib"

#######################################
# Ensure writable runtime directories exist
#######################################
mkdir -p "$MPL_CONFIG_DIR"

#######################################
# Ensure PostgreSQL container is running
#######################################
if [[ "$FISSURE_MODE" == "full" || "$FISSURE_MODE" == "base" || "$FISSURE_MODE" == "HIPRFISR" ]]; then
    cd "$FISSURE_DIR"

    if [ -f "$ENV_FILE" ]; then
        source "$ENV_FILE"
    else
        echo "[!] No .env file found — creating from example.env"
        cp example.env .env
        source .env
    fi

    echo "[*] Checking PostgreSQL container..."

    if ! sudo docker compose ps | grep -q "Up"; then
        echo "[*] Starting PostgreSQL container..."
        sudo docker compose up -d
    else
        echo "[✓] PostgreSQL container already running."
    fi

    echo "[*] Waiting for PostgreSQL to respond..."
    export PGPASSWORD="$POSTGRES_PASSWORD"

    until pg_isready \
        -U "$POSTGRES_USER" \
        -h "$POSTGRES_HOST" \
        -p "$POSTGRES_EXTERNAL_PORT" \
        >/dev/null 2>&1
    do
        sleep 2
    done

    echo "[✓] PostgreSQL ready."
fi

#######################################
# Prepare PulseAudio
#######################################
if [ -f "$HOME/.config/pulse/cookie" ]; then
    cp "$HOME/.config/pulse/cookie" /tmp/pulse-cookie
    chmod 644 /tmp/pulse-cookie
else
    echo "[!] PulseAudio cookie not found for $USER"
fi

#######################################
# Authorize local X11 access
#######################################
if command -v xhost >/dev/null 2>&1 && [ -n "$DISPLAY" ]; then
    xhost +SI:localuser:"$USER" >/dev/null
fi

#######################################
# Launch FISSURE Apptainer
#######################################
echo "[*] Launching FISSURE Apptainer..."

APPTAINER_ARGS=(
    shell
    --bind /run/udev:/run/udev
    --bind "$FISSURE_DIR:/opt/FISSURE"
    --bind "$MPL_CONFIG_DIR:/tmp/matplotlib"
    --env MPLCONFIGDIR=/tmp/matplotlib
)

#######################################
# Configure PulseAudio when available
#######################################
if [ -S "$XDG_RUNTIME_DIR/pulse/native" ]; then
    APPTAINER_ARGS+=(
        --bind "$XDG_RUNTIME_DIR/pulse:/tmp/pulse"
        --env PULSE_SERVER=unix:/tmp/pulse/native
        --env PULSE_COOKIE=/tmp/pulse-cookie
    )
fi

#######################################
# Configure graphical display
#######################################
if [ "$XDG_SESSION_TYPE" = "wayland" ]; then
    echo "[*] Wayland session detected."

    APPTAINER_ARGS+=(
        --bind /tmp/.X11-unix:/tmp/.X11-unix
        --env DISPLAY="$DISPLAY"
        --env QT_QPA_PLATFORM=xcb
    )
else
    echo "[*] X11 session detected."

    APPTAINER_ARGS+=(
        --bind /tmp/.X11-unix:/tmp/.X11-unix
        --env DISPLAY="$DISPLAY"
    )
fi

exec apptainer "${APPTAINER_ARGS[@]}" "$CONTAINER_DIR"