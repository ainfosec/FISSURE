import asyncio
import ssl
import fissure.utils
import os

async def send_cot(uid, lat, lon, alt, time, remarks):
    """ Sends CoT message to TAK server """

    #print("IN TAK SEND FUNCTION")
    
    # Get TAK server settings
    settings: dict = fissure.utils.get_fissure_config()
    s_addr = settings["tak"]["ip_addr"]
    s_port = settings["tak"]["port"]
    tak_cert = settings["tak"]["cert"]
    tak_key = settings["tak"]["key"]
    cot_msg = f"""<?xml version="1.0" encoding="UTF-8"?>
    <event version="2.0" type="a-f-G-U-H" uid="{uid}" how="m-g" time="{time}" start="{time}" stale="2029-08-09T18:18:06.521956Z">
        <detail>
            <contact callsign="{uid}"/>
            <remarks>"{remarks}"</remarks>
        </detail>
        <point lat="{lat}" lon="{lon}" ce="0" le="0" hae="0"/>
    </event>"""

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile=tak_cert, keyfile=tak_key)

    # Base directory where TAK server versions are installed
    tak_base_path = os.path.expanduser("~/Installed_by_FISSURE")

    # List directories, ignoring .zip files
    try:
        tak_dirs = [
            d for d in os.listdir(tak_base_path)
            if d.startswith("takserver-docker-") and os.path.isdir(os.path.join(tak_base_path, d))
        ]
        tak_dirs.sort(reverse=True)  # Sort to get the latest version first
        takserver_path = os.path.join(tak_base_path, tak_dirs[0]) if tak_dirs else None
    except FileNotFoundError:
        takserver_path = None  # Handle case where directory does not exist

    # Construct the full path to root-ca.pem
    if takserver_path:
        root_ca_path = os.path.join(takserver_path, "tak/certs/files/root-ca.pem")
    else:
        root_ca_path = None  # No TAK server found

    #print("Using TAK Root CA:", root_ca_path)
    
    context.load_verify_locations(root_ca_path)
    context.check_hostname = False
    
    try:
        reader, writer = await asyncio.open_connection(s_addr, s_port, ssl=context)
        writer.write(cot_msg.encode('utf-8'))
        await writer.drain()
        print("Message sent to TAK server.")
        await asyncio.sleep(1)  # Add a small delay before closing, prevents [SSL: APPLICATION_DATA_AFTER_CLOSE_NOTIFY] error
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print(f"Error sending to TAK: {e}")

async def send_cot_gps_update(uid, lat, lon, alt, time, remarks):
    """ Sends GPS update CoT message to TAK server """

    #print("IN TAK SEND FUNCTION")
    
    # Get TAK server settings
    settings: dict = fissure.utils.get_fissure_config()
    s_addr = settings["tak"]["ip_addr"]
    s_port = settings["tak"]["port"]
    tak_cert = settings["tak"]["cert"]
    tak_key = settings["tak"]["key"]
    cot_msg = f"""<?xml version="1.0" encoding="UTF-8"?>
    <event version="2.0" type="b-m-p-w" uid="{uid}" how="m-g" time="{time}" start="{time}" stale="2029-08-09T18:18:06.521956Z">
        <detail>
            <contact callsign="{uid}"/>
            <remarks>"{remarks}"</remarks>
        </detail>
        <point lat="{lat}" lon="{lon}" ce="0" le="0" hae="0"/>
    </event>"""

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile=tak_cert, keyfile=tak_key)

    # Base directory where TAK server versions are installed
    tak_base_path = os.path.expanduser("~/Installed_by_FISSURE")

    # List directories, ignoring .zip files
    try:
        tak_dirs = [
            d for d in os.listdir(tak_base_path)
            if d.startswith("takserver-docker-") and os.path.isdir(os.path.join(tak_base_path, d))
        ]
        tak_dirs.sort(reverse=True)  # Sort to get the latest version first
        takserver_path = os.path.join(tak_base_path, tak_dirs[0]) if tak_dirs else None
    except FileNotFoundError:
        takserver_path = None  # Handle case where directory does not exist

    # Construct the full path to root-ca.pem
    if takserver_path:
        root_ca_path = os.path.join(takserver_path, "tak/certs/files/root-ca.pem")
    else:
        root_ca_path = None  # No TAK server found

    #print("Using TAK Root CA:", root_ca_path)
    
    context.load_verify_locations(root_ca_path)
    context.check_hostname = False
    
    try:
        reader, writer = await asyncio.open_connection(s_addr, s_port, ssl=context)
        writer.write(cot_msg.encode('utf-8'))
        await writer.drain()
        print("Message sent to TAK server.")
        await asyncio.sleep(1)  # Add a small delay before closing, prevents [SSL: APPLICATION_DATA_AFTER_CLOSE_NOTIFY] error
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print(f"Error sending to TAK: {e}")

# Only run if executed directly (not when imported)
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('uid', type=str)
    parser.add_argument('lat', type=str)
    parser.add_argument('lon', type=str)
    parser.add_argument('alt', type=str)
    parser.add_argument('time', type=str)
    parser.add_argument('remarks', type=str)
    args = parser.parse_args()

    asyncio.run(send_cot(args.uid, args.lat, args.lon, args.alt, args.time, args.remarks))
