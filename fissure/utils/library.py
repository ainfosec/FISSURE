#!/usr/bin/env python3
import copy
import os
from dotenv import load_dotenv
import psycopg2
from psycopg2 import sql
from psycopg2.extensions import connection
from psycopg2 import OperationalError
from fissure.utils import FISSURE_ROOT, get_fg_library_dir
from decimal import Decimal
from datetime import datetime, date
import json
import re
from typing import List
import time


def openDatabaseConnection(retries=10, delay=2) -> connection:
    """
    Connects to the FISSURE database at the HIPRFISR computer/network.
    Waits for the database to be ready before connecting.
    
    Args:
        retries (int): Maximum number of retries before giving up.
        delay (int): Delay between retries in seconds.
    
    Returns:
        connection: A psycopg2 connection object to the database.
    """
    # Load environment variables from .env file
    load_dotenv(os.path.join(FISSURE_ROOT, ".env"))

    dbname = os.getenv('POSTGRES_DB')
    user = os.getenv('POSTGRES_USER')
    password = os.getenv('POSTGRES_PASSWORD')
    host = os.getenv('POSTGRES_HOST', 'localhost')
    port = os.getenv('POSTGRES_EXTERNAL_PORT', '5431')

    for attempt in range(retries):
        try:
            # Attempt to connect to the database
            conn = psycopg2.connect(
                dbname=dbname,
                user=user,
                password=password,
                host=host,
                port=port
            )
            print("Database connection established.")
            return conn
        except OperationalError as e:
            print(f"Database not ready, retrying in {delay} seconds... (Attempt {attempt + 1}/{retries})")
            time.sleep(delay)
    
    # Raise an exception if all retries are exhausted
    raise RuntimeError("Failed to connect to the database after multiple retries.")


def cacheTableData(source="Dashboard"):
    """
    Loads a copy of frequently used tables for local access and to avoid network queries to the database.
    """
    if source == "Dashboard":
        tables_to_load = [
            "archive_collection", 
            "archive_favorites", 
            "attack_categories",
            "protocols",
            "attacks",
            "demodulation_flow_graphs",
            "modulation_types",
            "packet_types",
            "soi_data"
        ]
    elif source == "Protocol Discovery":
        tables_to_load = [
            "protocols",
            "demodulation_flow_graphs",
            "modulation_types",
            "packet_types",
            "soi_data"
        ]
    else:
        tables_to_load = [
            "archive_collection", 
            "archive_favorites", 
            "attack_categories",
            "protocols",
            "attacks",
            "demodulation_flow_graphs",
            "modulation_types",
            "packet_types",
            "soi_data"
        ]

    # Load environment variables from .env file
    load_dotenv(os.path.join(FISSURE_ROOT,".env"))

    conn = None
    try:
        # Connect to PostgreSQL database
        conn = openDatabaseConnection()

        # Read Data
        table_data = {}
        with conn.cursor() as cur:
            for table_name in tables_to_load:
                query = f"SELECT * FROM {table_name};"
                cur.execute(query)
                rows = cur.fetchall()
                table_data[table_name] = [convert_data_types(row) for row in rows]
    
    except psycopg2.Error as e:
        print(f"Database error: {e}")

    finally:
        # Close the connection if it was successfully opened
        if conn is not None:
            conn.close()

    return table_data


def convert_data_types(row):
    """
    FissureZMQNode uses json.dumps() which needs decimal types to be converted to floats and datetimes to strings.
    """
    return [
        float(item) if isinstance(item, Decimal) 
        else item.isoformat() if isinstance(item, (datetime, date))
        else item
        for item in row
    ]


# =============================================================
#                   GET Direct Functions
# =============================================================
# This section contains functions for retrieving values 
# directly from the database accessed from inside the HIPRFISR 
# component.
# =============================================================


def getProtocolsDirect(conn):
    """
    Returns a list of protocol rows directly from the protocols table.
    """
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT protocol_name FROM protocols")
        rows = cur.fetchall()
        cur.close()

        return rows

    except Exception as e:
        print(f"Error: {e}")
        return []
    finally:
        if cur is not None:
            cur.close()


def getProtocolNamesDirect(conn):
    """
    Returns a sorted list of protocol names directly from the protocols table.
    """
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT protocol_name FROM protocols")
        rows = cur.fetchall()
        cur.close()

        # Convert list of tuples into a simple list
        protocol_names = sorted([row[0] for row in rows])

        return protocol_names
    
    except Exception as e:
        print(f"Error: {e}")
        return []
    finally:
        if cur is not None:
            cur.close()


def getModulationTypesDirect(conn, protocol):
    """
    Returns the modulation types for a protocol directly from the modulation_types table.
    """
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT modulation_type FROM modulation_types WHERE protocol = %s", (protocol,))
        get_modulation_types = cur.fetchall()
        cur.close()

        # Convert list of tuples into a simple list
        sorted_modulation_types = sorted(item[0] for item in get_modulation_types)

        return sorted_modulation_types
    
    except Exception as e:
        print(f"Error: {e}")
        return []
    finally:
        if cur is not None:
            cur.close()


def getPacketTypesDirect(conn, protocol):
    """
    Returns a list of sorted packet types for a protocol from the packet_types table.
    """
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT packet_name FROM packet_types WHERE protocol = %s", (protocol,))
        get_packet_types = cur.fetchall()
        cur.close()

        # Convert list of tuples into a simple list
        sort_order_packet_types = [(int(row[5]), str(row[2])) for row in get_packet_types]
        sorted_packet_names = [string for _, string in sorted(sort_order_packet_types)]

        return sorted_packet_names
    
    except Exception as e:
        print(f"Error: {e}")
        return []
    finally:
        if cur is not None:
            cur.close()

    
def classifyFrequencyFromTextDirect(text, protocol_only=False):
    """
    Extracts a frequency from the given text (supports HackRF sweep formats
    and generic MHz/kHz/Hz formats), performs a direct database lookup on
    frequency_lookup, and returns a clean formatted summary string.

    Returns:
        ""  → if no frequency found
        "[...]" → classification result
    """
    # ---------------------------------------------------------------------------
    # PRIORITY SCALE FOR FREQUENCY CLASSIFICATION (MANUAL SYSTEM)
    #
    # The `priority` field is a **manually assigned value** used to rank
    # overlapping frequency ranges in the frequency_lookup table.
    #
    # There is **no automatic scoring or inference**. The classifier simply
    # returns all matching rows sorted by:
    #
    #       ORDER BY priority DESC
    #
    # The first result in the list becomes `best_match`.
    #
    # Recommended manual scale:
    #
    #   10 – Most important / most likely protocol in this band.
    #        e.g., WiFi channels in 2.4 GHz and 5 GHz.
    #
    #    7 – Very common narrowband protocols.
    #        e.g., BLE advertising, BT Classic.
    #
    #    5 – Typical IoT / home automation.
    #        e.g., Z-Wave, TPMS.
    #
    #    3 – Rare or low-duty-cycle signals.
    #        e.g., X10, specialized ISM devices.
    #
    #    1 – Weak, ambiguous, or uncertain match.
    #
    #    0 – Default / unassigned.
    #        Valid entry but NOT considered a primary match.
    #
    # Notes:
    #   - Changing priority values must be done manually in the database.
    #   - This system is intentionally simple because priority is subjective
    #     and operationally dependent.
    #   - Future ML scoring or heuristic logic can layer on top of this if needed.
    # ---------------------------------------------------------------------------

    # ------------------------------------------------------------------
    # 1. HackRF sweep format: f:310,310,310,...
    # ------------------------------------------------------------------
    freq_hz = None
    m_hackrf = re.search(r"f:([\d\.,]+)", text)
    if m_hackrf:
        freq_list = m_hackrf.group(1).split(',')
        try:
            first_val_mhz = float(freq_list[0])
            freq_hz = first_val_mhz * 1e6  # HackRF sweep is always MHz
        except Exception:
            freq_hz = None

    # ------------------------------------------------------------------
    # 2. Generic frequency format (only if HackRF pattern didn't work)
    # ------------------------------------------------------------------
    if freq_hz is None:
        m = re.search(r"(\d+(\.\d+)?)\s*(MHz|mhz|kHz|khz|Hz|hz)?", text)
        if not m:
            return ""  # No frequency found

        value = float(m.group(1))
        unit = (m.group(3) or "").lower()

        # Normalize to Hz
        if unit == "mhz":
            freq_hz = value * 1e6
        elif unit == "khz":
            freq_hz = value * 1e3
        elif unit == "hz":
            freq_hz = value
        else:
            # No unit — assume MHz for small values (2412 → 2412 MHz)
            # but assume Hz if value is very large
            freq_hz = value * 1e6 if value < 1e4 else value

    # At this point, freq_hz is a clean float in Hz ---------------------

    # ------------------------------------------------------------------
    # 3. DIRECT DB LOOKUP (fully inlined version of classifyFrequencyDirect)
    # ------------------------------------------------------------------
    conn = None
    cur = None

    try:
        # Open short-lived connection (safe for concurrent TAK + alerts)
        conn = openDatabaseConnection()
        cur = conn.cursor()

        query = """
            SELECT freq_low, freq_high, protocol_name, region, priority, notes
            FROM frequency_lookup
            WHERE freq_low <= %s AND freq_high >= %s
            ORDER BY priority DESC;
        """

        cur.execute(query, (freq_hz, freq_hz))
        rows = cur.fetchall()

        # No matches? Return a readable message
        if not rows:
            return f"[No known protocols for {freq_hz/1e6:.3f} MHz]"

        # Best match is the first (highest priority)
        best = {
            "freq_low":      rows[0][0],
            "freq_high":     rows[0][1],
            "protocol_name": rows[0][2],
            "region":        rows[0][3],
            "priority":      rows[0][4],
            "notes":         rows[0][5],
        }

        proto  = best["protocol_name"]
        region = best["region"] or "Any"
        notes  = best["notes"] or ""
        prio   = best["priority"]

        if protocol_only:
            return proto

        summary = (
            f"[Protocol={proto} | Region={region} | "
            f"Priority={prio} | Notes={notes.strip()}]"
        )

        return summary

    except Exception as e:
        return f"[Frequency classification error: {e}]"

    finally:
        if cur is not None:
            try:
                cur.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass



# =============================================================
#                   GET Indirect Functions
# =============================================================
# This section contains functions for retrieving values from 
# the smaller cached FISSURE library/database accessed from
# outside the HIPRFISR component.
# =============================================================

def getConditionerFilepath(library, isolation_category, isolation_method, hardware, data_type, version):
    """
    Returns the isolation methods from the conditioner_flow_graphs table.
    """
    return next(
        (
            (str(row[10]), str(row[4]))
            for row in library["conditioner_flow_graphs"]
            if (
                row[1] == isolation_category
                and row[2] == isolation_method
                and row[3] == hardware
                and row[5] == data_type
                and row[6] == version
            )
        ),
        None,
    )

def getConditionerIsolationCategory(library, hardware, version):
    """
    Returns the isolation categories from the conditioner_flow_graphs table.
    """
    # Define priority values to always include
    priority_values = [
        "Energy - Burst Tagger", 
        "Energy - Imagery",
        "Eigenvalue",
        "Matched Filter",
        "Cyclostationary"        
    ]

    # Get unique categories from the library
    categories = {str(row[1]) for row in library["conditioner_flow_graphs"] if row[3] == hardware and row[6] == version}

    # Add priority values to the set
    categories.update(priority_values)

    # Return a sorted list
    return sorted(categories)


def getConditionerIsolationMethod(library, isolation_category, version, hardware):
    """
    Returns the isolation methods from the conditioner_flow_graphs table.
    """
    return sorted([str(row[2]) for row in library["conditioner_flow_graphs"] if row[1] == isolation_category and row[3] == hardware and row[6] == version])


def getConditionerRow(library, isolation_method, version, hardware):
    """
    Returns the row for a conditioner isolation method from the conditioner_flow_graphs table.
    """
    matching_rows = [row for row in library["conditioner_flow_graphs"] if row[2] == isolation_method and row[3] == hardware and row[6] == version]
    
    return matching_rows[0] if matching_rows else None


def getDetectorFlowGraphsFilename(library, detector_type, hardware, version):
    """
    Returns a list of filename values for a detector type, hardware type, and version from the detector_flow_graphs table.
    """
    return [str(row[3]) for row in library["detector_flow_graphs"] if row[1] == detector_type and row[2] == hardware and row[5] == version]


def getInspectionFlowGraphs(library):
    """
    Returns the inspection_flow_graphs table contents.
    """
    return [row for row in library["inspection_flow_graphs"]]


def getInspectionFlowGraphFilename(library, hardware, version):
    """
    Returns a list of python_file values for a hardware type and version from the inspection_flow_graphs table.
    """
    return [str(row[2]) for row in library["inspection_flow_graphs"] if row[1] == hardware and row[3] == version]


def getProtocolsTable(library):
    """
    Returns the protocols table contents.
    """
    return [row for row in library["protocols"]]


def getProtocols(library):
    """
    Returns a list of protocols from the protocols table.
    """
    return [str(row[1]) for row in library["protocols"]]


def getProtocolDataRates(library, protocol):
    """
    Returns a list of data rates for a protocol from the protocols table.
    """
    data_rates = [row[2] for row in library["protocols"] if row[1] == protocol]

    return data_rates


def getProtocolMedianPacketLengths(library, protocol, statistic):
    """
    Returns a list of median packet lengths for a protocol from the protocols table.
    """
    median_packet_lengths = [row[3] for row in library["protocols"] if row[1] == protocol]

    return median_packet_lengths


def getPacketTypesTable(library):
    """
    Returns the packet_types table contents.
    """
    return [row for row in library["packet_types"]]


def getPacketTypes(library, protocol):
    """
    Returns a list of sorted packet types for a protocol from the packet_types table.
    """
    sort_order_packet_types = [(int(row[5]), str(row[2])) for row in library["packet_types"] if row[1] == protocol]
    sorted_packet_types = [string for _, string in sorted(sort_order_packet_types)]

    return sorted_packet_types


def getArchiveFavorites(library):
    """
    Returns a list of sorted Archive favorites from the archive_favorites table.
    """
    return sorted(library["archive_favorites"], key=lambda x: x[1])


def getArchiveCollection(library):
    """
    Returns a list of Archive collections with no parent IDs (parent folder).
    """
    return [row for row in library["archive_collection"]]


def getArchiveCollectionParent(library):
    """
    Returns a list of Archive collections with no parent IDs (parent folder).
    """
    return sorted([row for row in library["archive_collection"] if row[8] is None], key=lambda x: x[1])


def getArchiveCollectionSubdirectory(library, parent_id):
    """
    Returns a list of Archive collection subdirectories from a parent ID.
    """
    return sorted([row for row in library["archive_collection"] if row[8] == parent_id], key=lambda x: x[1])


def getArchiveCollectionFilepath(library, name, parent1, parent2):
    """
    Returns the filepath (zipped, .tar) of a collection filtered by (unique) name from the archive_collection table).
    """
    # Root Tar File
    if parent1 == None:
        get_filepath = next((row[3] for row in library["archive_collection"] if row[1] == name), None)
        if get_filepath == None:
            return None

    elif parent2 == None:
        if '.sigmf-data' in name:
            # Single Data File with a Single Parent (1MSps_Exampes/avent_scd560_1922_5MHz_1MSps_1.sigmf-data)
            parent1_filepath = next((row[3] for row in library["archive_collection"] if row[1] == parent1), None)
            if parent1_filepath == None:
                return None
            
            get_filepath = parent1_filepath.replace('.tar','') + '/' + name
        else:
            # Child Collection (Avent_SCD560, CW_Morse_Code, etc.)
            parent1_filepath = next((row[3] for row in library["archive_collection"] if row[1] == parent1), None)
            if parent1_filepath == None:
                return None

            get_filepath = parent1_filepath.replace('.tar','') + '/' + name + '.tar'

    else:
        # Single Data File with Two Parents (X3xx_1MSps_All/Avent_SCD560/avent_scd560_1922_5MHz_1MSps_1.sigmf-data)
        if parent1 == None or parent2 == None:
            return None 
        
        parent2_filepath = next((row[3] for row in library["archive_collection"] if row[1] == parent2), None)
        if parent2_filepath == None:
            return None
        
        get_filepath = parent2_filepath.replace('.tar','') + '/' + parent1 + '/' + name
    
    return get_filepath


def getAttackNames(library, protocol, version):
    """
    Returns the attack_name for a protocol and version in the attacks table.
    """
    exclude_list = [
        "Single-Stage",
        "Denial of Service",
        "Jamming",
        "Spoofing",
        "Sniffing/Snooping",
        "Probe Attacks",
        "Installation of Malware",
        "Misuse of Resources",
        "File",
        "Multi-Stage",
        "New Multi-Stage",
        "Fuzzing",
        "Variables",
    ]
    attack_names = [row[2] for row in library["attacks"] if row[1] == protocol and row[2] not in exclude_list and row[8] == version]

    return attack_names


def getAttackType(library, protocol, attack_name, modulation_type, hardware, version):
    """
    Returns the attack_type for an attack in the attacks table.
    """
    attack_name = attack_name.split(' - ')[-1].strip()  # Avoids "X10 - On" in attack tree when entered as "On" in attacks table
    attack_type = next((row[5] for row in library["attacks"] if row[1] == protocol and row[2] == attack_name and row[3] == modulation_type and row[4] == hardware and row[8] == version), None)

    return attack_type


def getAttackFilename(library, protocol, attack_name, modulation_type, hardware, version):
    """
    Returns the filename for an attack in the attacks table.
    """
    attack_name = attack_name.split(' - ')[-1].strip()  # Avoids "X10 - On" in attack tree when entered as "On" in attacks table
    attack_filename = next((row[6] for row in library["attacks"] if row[1] == protocol and row[2] == attack_name and row[3] == modulation_type and row[4] == hardware and row[8] == version), None)

    return attack_filename


def getAttacks(library, protocol, version):
    """
    Returns the rows of attack data for a protocol in the attacks table.
    """
    if protocol == None:
        if version == None:
            attack_rows = [row for row in library["attacks"]]
        else:
            attack_rows = [row for row in library["attacks"] if row[8] == version]
    else:
        if version == None:
            attack_rows = [row for row in library["attacks"] if row[1] == protocol]
        else:
            attack_rows = [row for row in library["attacks"] if row[1] == protocol and row[8] == version]

    return attack_rows


def getAttackCategories(library):
    """
    Returns the rows of attack categories from the attack_categories table.
    """
    attack_categories_rows = [row for row in library["attack_categories"]]

    return attack_categories_rows


def getAttackCategoryNames(library):
    """
    Returns the names of the attack categories from the attack_categories table.
    """
    attack_category_names = [row[1] for row in library["attack_categories"]]

    return attack_category_names


def getSingleStageAttacks(library, version):
    """
    Returns the contents of the attacks table (id, attack_name, and tree_indent).
    """
    return library["attacks"]


def getSingleStageAttackNames(library, version):
    """
    Returns the attack_name of each row in the attacks table.
    """
    return [row[1] + ' - ' + row[2] for row in library["attacks"]]


def getMultiStageAttackNames(library, version):
    """
    Returns the attack_name of each row in the attacks table if the category is "Multi-Stage".
    """
    return [row[2] for row in library["attacks"] if row[7] == "Multi-Stage"]


def getFields(library, protocol, packet_name):
    """
    Returns the sorted field names (no data) for a protocol and packet type from the packet_types table.
    """
    if len(protocol) == 0 or len(packet_name) == 0:
        return []
    
    fields = next(packet_type[4] for packet_type in library["packet_types"]
                  if packet_type[1] == protocol and 
                  packet_type[2] == packet_name)

    sorted_fields_list = sorted(fields, key=lambda x: fields[x]["Sort Order"])

    return sorted_fields_list


def getFieldData(library, protocol, packet_name, field_name):
    """
    Returns the field dictionary for a protocol, packet_name, and field_name from the packet_types table.
    """
    fields = next(packet_type[4] for packet_type in library["packet_types"]
                  if packet_type[1] == protocol and 
                  packet_type[2] == packet_name)
    
    field_dictionary = fields[field_name]

    return field_dictionary


def getFieldDataAll(library, protocol, packet_name):
    """
    Returns the whole field dictionary for a protocol, packet_name, the packet_types table.
    """
    fields = next(packet_type[4] for packet_type in library["packet_types"]
                  if packet_type[1] == protocol and 
                  packet_type[2] == packet_name)

    return fields


def getDemodulationFlowGraphs(library):
    """
    Returns the demdulation_flow_graph table contents.
    """
    return [row for row in library["demodulation_flow_graphs"]]


def getDemodulationFlowGraphFilenames(library, protocol=None, modulation=None, hardware=None, version=None):
    """
    Returns the demdulation flow graph filename for a protocol, modulation, hardware type, and version combination.
    """
    # Start with all flow graphs
    demod_flowgraphs = library["demodulation_flow_graphs"]
    # Filter based on provided arguments
    if protocol:
        demod_flowgraphs = [row for row in demod_flowgraphs if row[1] == protocol]
    if modulation:
        demod_flowgraphs = [row for row in demod_flowgraphs if row[2] == modulation]
    if hardware:
        demod_flowgraphs = [row for row in demod_flowgraphs if row[3] == hardware]
    if version:
        demod_flowgraphs = [row for row in demod_flowgraphs if row[6] == version]

    return [row[4] for row in demod_flowgraphs]


def getDemodulationFlowGraphsModulation(library, protocol=None, version=None):
    """
    Returns the modulation types for a protocol's demodulation flow graphs in the demodulation_flow_graphs table.
    """
    get_modulation_types = []
    if protocol:
        get_modulation_types = [row[2] for row in library["demodulation_flow_graphs"] if row[1] == protocol and row[6] == version]
    else:
        get_modulation_types = [row[2] for row in library["demodulation_flow_graphs"] if row[6] == version]

    return get_modulation_types


def getDemodulationFlowGraphsSnifferType(library, filename, version):
    """
    Returns the sniffer types for a protocol's demodulation flow graph filename in the demodulation_flow_graphs table.
    """
    get_sniffer_types = []
    if filename:
        get_sniffer_types = [row[5] for row in library["demodulation_flow_graphs"] if row[4] == filename and row[6] == version]
    else:
        get_sniffer_types = [row[5] for row in library["demodulation_flow_graphs"] if row[6] == version]

    return get_sniffer_types


def getDemodulationFlowGraphsHardware(library, protocol=None, modulation=None, version=None):
    """
    Returns the demodulation flow graph hardware types for a protocol, modulation type, and version in the demodulation_flow_graphs table.
    """
    # Start with all flow graphs
    hardware_list = library["demodulation_flow_graphs"]
    
    # Filter based on provided arguments
    if protocol:
        hardware_list = [row[3] for row in hardware_list if row[1] == protocol]
    if modulation:
        hardware_list = [row[3] for row in hardware_list if row[2] == modulation]
    if version:
        hardware_list = [row[3] for row in hardware_list if row[6] == version]

    return hardware_list


def getDissector(library, protocol, packet_name):
    """
    Returns the dissector filename and port of a dissector for a packet type with a matching protocol and packet_name.
    """
    dissectors = [row[3] for row in library["packet_types"] if row[1] == protocol and row[2] == packet_name]
    
    if dissectors:
        return dissectors[0]  # Return the first matching result
    else:
        return None  # Or handle the case when nothing is found


def getNextDissectorPort(library):
    """
    Returns an unassigned dissector UDP port.
    """
    all_dissector_ports = [
        int(row[3]["Port"]) for row in library["packet_types"] 
        if row[3].get("Port") not in [None, 'None']  # Filter out both None and 'None'
    ]

    if all_dissector_ports:  # Ensure the list is not empty
        max_value = max(all_dissector_ports)
        return max_value + 1
    else:
        # Handle the case when there are no valid ports
        return 1  # Return 1 or any default starting port number


def getDefaults(library, protocol, packet_name):
    """
    Returns default values for fields in the fields dictionary sorted by field sort order in the packet_types table.
    """
    sorted_fields = getFields(protocol, packet_name)
    
    default_field_data = []
    for field in default_field_data:
        default_field_data.append(row[4][field]["Default Value"] for row in library["packet_types"] if row[1] == protocol and row[2] == packet_name and field in row[4])

    return default_field_data


def getModulationTypes(library):
    """
    Returns the modulation_types table contents.
    """
    return [row for row in library["modulation_types"]]


def getModulations(library, protocol):
    """
    Returns the modulation types for a protocol from the modulation_types table.
    """
    modulations = [row[2] for row in library["modulation_types"] if row[1] == protocol]

    return modulations


def getSOI_Names(library, protocol):
    """
    Returns a list of all soi_name values for a protocol from the soi_data table.
    """
    all_soi_names = [row[2] for row in library["soi_data"] if row[1] == protocol]

    return all_soi_names


def getSOIs(library, protocol=None):
    """
    Returns a list of all the SOIs for a protocol from the soi_data table.
    """
    if protocol == None:
        protocol_sois = [row for row in library["soi_data"]]
    else:
        protocol_sois = [row for row in library["soi_data"] if row[1] == protocol]

    return protocol_sois


def getTriggersTable(library):
    """
    Returns the trigger table contents.
    """
    return [row for row in library["triggers"]]


def getTriggerCategories(library, version):
    """
    Returns a sorted unique list of trigger categories from the triggers table.
    """
    return sorted(list(set([row[1] for row in library["triggers"] if row[6] == version])))


def getTriggerNames(library, category, version):
    """
    Returns a sorted unique list of trigger names filtered by category from the triggers table.
    """
    return sorted(list(set([row[2] for row in library["triggers"] if row[1] == category and row[6] == version])))


def getTriggerFilename(library, category, trigger_name, version):
    """
    Returns the trigger filename filtered by category and trigger_name from the triggers table.
    """
    return next((row[4] for row in library["triggers"] if row[1] == category and row[2] == trigger_name and row[6] == version), None)


def getTriggerFileType(library, category, trigger_name, version):
    """
    Returns the trigger file_type filtered by category and trigger_name from the triggers table.
    """
    return next((row[5] for row in library["triggers"] if row[1] == category and row[2] == trigger_name and row[6] == version), None)


def getTriggerDefaultSettings(library, category, trigger_name, version):
    """
    Returns the trigger file_type filtered by category and trigger_name from the triggers table.
    """
    return next((row[3] for row in library["triggers"] if row[1] == category and row[2] == trigger_name and row[6] == version), None)


def getConditionerFlowGraphsTable(library):
    """
    Returns all rows in the conditioner_flow_graphs table.
    """
    return [row for row in library["conditioner_flow_graphs"]]


def getDetectorFlowGraphsTable(library):
    """
    Returns all rows in the detector_flow_graphs table.
    """
    return [row for row in library["detector_flow_graphs"]]


# =============================================================
#                        ADD Functions
# =============================================================
# This section contains functions for adding values to the 
# FISSURE library/database.
# =============================================================

def addTableRow(conn: connection, table_name: str, columns: List[str], values: List):
    """
    Adds a new row to any FISSURE PostgreSQL database table.

    Parameters:
        conn (connection): A psycopg2 connection object.
        table_name (str): The name of the table where the row will be added.
        columns (List[str]): A list of column names to insert values into.
        values (List): A list of values corresponding to the columns.

    Raises:
        Exception: Propagates any exception that occurs during the database operation.
    """
    cur = None
    try:
        # print("1111")
        # print(f"Columns: {columns}")
        # print(f"Values: {values}")

        # Validate input
        if not columns or not values or len(columns) != len(values):
            raise ValueError("The number of columns and values must match.")

        # Replace 'None' (string) with Python None for JSON columns
        processed_values = [None if value == 'None' else value for value in values]

        # Create cursor
        cur = conn.cursor()

        # Build the SQL query dynamically
        query = sql.SQL("""
            INSERT INTO {table} ({columns})
            VALUES ({placeholders})
        """).format(
            table=sql.Identifier(table_name),
            columns=sql.SQL(", ").join(map(sql.Identifier, columns)),
            placeholders=sql.SQL(", ").join(sql.Placeholder() for _ in processed_values)
        )

        # print(f"Query: {query.as_string(conn)}")
        # print(f"Processed Values: {processed_values}")

        # Execute the query
        cur.execute(query, processed_values)

        # Commit the transaction
        conn.commit()
        # print(f"Row inserted into {table_name}: {processed_values}")

    except Exception as e:
        # Rollback in case of an error
        conn.rollback()
        print(f"Error inserting row into {table_name}: {e}")
        raise

    finally:
        # Close the cursor
        if cur:
            cur.close()


def addArchiveCollection(name, file_list, filepath, files, format, size, notes, parent_id):
    """
    Adds a new archive_collection table to the FISSURE PostgreSQL library.
    """
    # Load environment variables from .env file
    load_dotenv(os.path.join(FISSURE_ROOT,".env"))

    # Connect to PostgreSQL database
    conn = psycopg2.connect(
        dbname = os.getenv('POSTGRES_DB'),
        user = os.getenv('POSTGRES_USER'),
        password = os.getenv('POSTGRES_PASSWORD'),
        host = os.getenv('POSTGRES_HOST', 'localhost'),
        port = os.getenv('POSTGRES_EXTERNAL_PORT', '5431')
    )
    cur = conn.cursor()

    # SQL Insert command
    insert_query = """
        INSERT INTO archive_collection (name, file_list, filepath, files, format, size, notes, parent_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """

    # Data to be inserted
    get_data = (name, file_list, filepath, files, format, size, notes, parent_id)
    # data = [
    #     ('X3xx_10MSps_All', None, '/X3xx/10MSps.tar', 75, 'Complex Float 32', 1.8, 
    #     'A collection of signals from miscellaneous devices recorded by Assured Information Security.', 
    #     None),
    #     ('Avent_SCD560', 
    #     ['avent_scd560_1922_5MHz_10MSps_1.sigmf-data', 
    #     'avent_scd560_1922_5MHz_10MSps_2.sigmf-data', 
    #     'avent_scd560_1922_5MHz_10MSps_3.sigmf-data', 
    #     'avent_scd560_1922_5MHz_10MSps_4.sigmf-data', 
    #     'avent_scd560_1922_5MHz_10MSps_5.sigmf-data'], 
    #     None, 5, 'Complex Float 32', 0.1796, '', 1)
    # ]

    # Execute the query
    cur.execute(insert_query, get_data)

    # Commit the transaction
    conn.commit()

    # Close communication
    cur.close()
    conn.close()


def addArchiveFavorite(file_name, date, format, modulation, notes, protocol, sample_rate, samples, size, tuned_frequency):
    """
    Adds a new entry to the archive_favorites table in the FISSURE PostgreSQL library.
    """
    # Load environment variables from .env file
    load_dotenv()

    # Connect to PostgreSQL database
    conn = psycopg2.connect(
        dbname=os.getenv('POSTGRES_DB'),
        user=os.getenv('POSTGRES_USER'),
        password=os.getenv('POSTGRES_PASSWORD'),
        host=os.getenv('POSTGRES_HOST', 'localhost'),
        port=os.getenv('POSTGRES_EXTERNAL_PORT', '5431')
    )
    cur = conn.cursor()

    # SQL Insert command for the archive_favorites table
    insert_query = """
        INSERT INTO archive_favorites (file_name, date, format, modulation, notes, protocol, sample_rate, samples, size, tuned_frequency)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    # Data to be inserted
    get_data = (file_name, date, format, modulation, notes, protocol, sample_rate, samples, size, tuned_frequency)

    # Execute the query
    cur.execute(insert_query, get_data)

    # Commit the transaction
    conn.commit()

    # Close communication
    cur.close()
    conn.close()


def addProtocol(conn: connection, protocol_name: str, data_rates: float=None, median_packet_lengths: float=None):
    """
    Adds a new protocol_name to the protocols table.
    """
    cur = None
    try:
        cur = conn.cursor()

        # Check if the second column already has the value
        check_query = sql.SQL("SELECT 1 FROM protocols WHERE protocol_name = %s")
        cur.execute(check_query, (protocol_name,))
        result = cur.fetchone()

        # If no matching value in column2, insert the new row
        if result is None:
            insert_query = sql.SQL(
                "INSERT INTO {} (protocol_name, data_rates, median_packet_lengths) VALUES (%s, %s, %s)"
            ).format(sql.Identifier("protocols"))
            
            cur.execute(insert_query, (protocol_name, None, None))
            conn.commit()
            print("Row inserted successfully.")
        else:
            print("Row with protocol_name value '{}' already exists.".format(protocol_name))

    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()  # Rollback in case of error
    finally:
        if cur is not None:
            cur.close()


def addModulationType(conn: connection, protocol: str, modulation_type: str):
    """
    Adds a new modulation type to the modulation_types table.
    """
    cur = None
    try:
        cur = conn.cursor()

        # Check if the columns already have the values
        check_query = sql.SQL("SELECT 1 FROM modulation_types WHERE protocol = %s AND modulation_type = %s")
        cur.execute(check_query, (protocol, modulation_type))
        result = cur.fetchone()

        # If no matching value, insert the new row
        if result is None:
            insert_query = sql.SQL(
                "INSERT INTO {} (protocol, modulation_type) VALUES (%s, %s)"
            ).format(sql.Identifier("modulation_types"))
            
            cur.execute(insert_query, (protocol, modulation_type))
            conn.commit()
            print("Row inserted successfully.")
        else:
            print(f"Row with modulation_type '{modulation_type}' for protocol '{protocol}' already exists.")

    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()  # Rollback in case of error
    finally:
        if cur is not None:
            cur.close()


def addPacketType(conn: connection, protocol: str, packet_name: str, dissector: dict, fields: dict, sort_order: int):
    """
    Adds a new packet type to the packet_types table.
    """
    cur = None
    try:
        cur = conn.cursor()

        # Check if the columns already has the values
        check_query = sql.SQL("SELECT 1 FROM packet_types WHERE protocol = %s AND packet_name = %s")
        cur.execute(check_query, (protocol, packet_name))
        result = cur.fetchone()

        # If no matching value, insert the new row
        if result is None:
            # Convert dictionaries to JSON strings
            dissector_json = dissector if dissector.__class__ is str else json.dumps(dissector)
            fields_json = fields if fields.__class__ is str else json.dumps(fields)

            insert_query = sql.SQL(
                "INSERT INTO packet_types (protocol, packet_name, dissector, fields, sort_order) VALUES (%s, %s, %s, %s, %s)"
            )
            
            cur.execute(insert_query, (protocol, packet_name, dissector_json, fields_json, sort_order))
            conn.commit()
            print("Row inserted successfully.")
        else:
            print(f"Row with packet name '{packet_name}' for protocol '{protocol}' already exists.")

    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()  # Rollback in case of error
    finally:
        if cur is not None:
            cur.close()


def addSOI(conn: connection, protocol: str, soi_name: str, center_frequency: float, start_frequency: float, end_frequency: float, bandwidth: float, continuous: str, modulation: str, notes: str):
    """
    Adds a signal of interest (SOI) to the soi_data table.
    """
    cur = None
    try:
        cur = conn.cursor()

        # Check if the columns already has the values
        check_query = sql.SQL("SELECT 1 FROM soi_data WHERE protocol = %s AND soi_name = %s")
        cur.execute(check_query, (protocol, soi_name))
        result = cur.fetchone()

        # If no matching value, insert the new row
        if result is None:
            insert_query = sql.SQL(
                """
                INSERT INTO soi_data (
                    protocol,
                    soi_name,
                    center_frequency,
                    start_frequency,
                    end_frequency,
                    bandwidth,
                    continuous,
                    modulation,
                    notes
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
            )
            
            cur.execute(insert_query, (protocol, soi_name, center_frequency, start_frequency, end_frequency, bandwidth, continuous, modulation, notes))
            conn.commit()
            print("Row inserted successfully.")
        else:
            print(f"Row with SOI name '{soi_name}' for protocol '{protocol}' already exists.")

    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()  # Rollback in case of error
    finally:
        if cur is not None:
            cur.close()


def addDemodulationFlowGraph(conn: connection, protocol: str, modulation_type: str, hardware: str, filename: str, output_type: str, version: str):
    """
    Adds a demodulation flow graph to the demodulation_flow_graphs table.
    """
    cur = None
    try:
        cur = conn.cursor()

        # Check if the columns already has the values
        check_query = sql.SQL("SELECT 1 FROM demodulation_flow_graphs WHERE protocol = %s AND filename = %s")
        cur.execute(check_query, (protocol, filename))
        result = cur.fetchone()

        # If no matching value, insert the new row
        if result is None:
            insert_query = sql.SQL(
                """
                INSERT INTO demodulation_flow_graphs (
                    protocol,
                    modulation_type,
                    hardware,
                    filename,
                    output_type
                ) VALUES (%s, %s, %s, %s, %s)
                """
            )
            
            cur.execute(insert_query, (protocol, modulation_type, hardware, filename, output_type))
            conn.commit()
            print("Row inserted successfully.")
        else:
            print(f"Row with filename '{filename}' for protocol '{protocol}' already exists.")

    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()  # Rollback in case of error
    finally:
        if cur is not None:
            cur.close()


def addAttack(conn: connection, protocol: str, attack_name: str, modulation_type: str, hardware: str, attack_type: str, filename: str, category_name: str, version: str):
    """
    Adds a new attack to the attacks table.
    """
    cur = None
    try:
        cur = conn.cursor()

        # Check if the columns already has the values
        check_query = sql.SQL("SELECT 1 FROM attacks WHERE protocol = %s AND filename = %s")
        cur.execute(check_query, (protocol, filename))
        result = cur.fetchone()

        # If no matching value, insert the new row
        if result is None:
            insert_query = sql.SQL(
                """
                INSERT INTO attacks (
                    protocol,
                    attack_name,
                    modulation_type,
                    hardware,
                    attack_type,
                    filename,
                    category_name,
                    version
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """
            )
            
            cur.execute(insert_query, (protocol, attack_name, modulation_type, hardware, attack_type, filename, category_name, version))
            conn.commit()
            print("Row inserted successfully.")
        else:
            print(f"Row with filename '{filename}' for protocol '{protocol}' already exists.")

    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()  # Rollback in case of error
    finally:
        if cur is not None:
            cur.close()


def addDissector(conn, protocol, packet_name, dissector_filename, dissector_port):
    """
    Replaces the dissector filename and port for a packet type in the packet_types table. 
    There should only be one dissector per packet type.
    """
    cur = None
    try:
        cur = conn.cursor()

        new_value = json.dumps({"Port": int(dissector_port), "Filename": str(dissector_filename)})

        # Construct the SQL query
        update_query = """
        UPDATE packet_types
        SET dissector = %s
        WHERE protocol = %s AND packet_name = %s;
        """

        # Execute the query with the appropriate parameters
        cur.execute(update_query, (
            new_value,
            protocol,
            packet_name
        ))
        conn.commit()

    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()  # Rollback in case of error
    finally:
        if cur is not None:
            cur.close()


# def newProtocol(protocolname="", attacks={}, demodflowgraph="", modtype="", pkttypes=newPacket()):
#     """Adds an empty protocol to a library."""

#     new_protocol_dict = {protocolname: {"Null Placeholder": None}}

#     return new_protocol_dict

# =============================================================
#                        REMOVE Functions
# =============================================================
# This section contains functions for removing values from the
# FISSURE library/database.
# =============================================================

def removeFromTable(conn, table_name, row_id, delete_files, os_version):
    """
    Removes a row from a table in the database.
    """
    cur = None
    try:
        cur = conn.cursor()

        # Remove Files
        if delete_files == True:
            if table_name == "demodulation_flow_graphs":
                # Use parameterized query to prevent SQL injection
                query = f"SELECT filename FROM {table_name} WHERE id = %s;"
                cur.execute(query, (row_id,))
                result = cur.fetchone()
                
                # If the row exists, fetch the filename, delete the file
                if result:
                    get_filename = result[0]  # Not the column value. Returns a tuple (filename,)
                    get_filepath = os.path.join(get_fg_library_dir(os_version), "PD Flow Graphs", get_filename)
                    if os.path.exists(get_filepath):
                        os.remove(get_filepath)
                        print(f"Deleted: {get_filepath}")
                    else:
                        print(f"File not found: {get_filepath}")
                    grc_filepath = get_filepath.replace(".py",".grc")
                    if os.path.exists(grc_filepath):
                        os.remove(grc_filepath)
                        print(f"Deleted: {grc_filepath}")
                    else:
                        print(f"File not found: {grc_filepath}")

            elif table_name == "inspection_flow_graphs":
                # Use parameterized query to prevent SQL injection
                query = f"SELECT python_file FROM {table_name} WHERE id = %s;"
                cur.execute(query, (row_id,))
                result = cur.fetchone()
                
                # If the row exists, fetch the filename, delete the file
                if result:
                    get_filename = result[0]
                    get_filepath = os.path.join(get_fg_library_dir(os_version), "Inspection Flow Graphs", get_filename)
                    if os.path.exists(get_filepath):
                        os.remove(get_filepath)
                        print(f"Deleted: {get_filepath}")
                    else:
                        print(f"File not found: {get_filepath}")
                    grc_filepath = get_filepath.replace(".py",".grc")
                    if os.path.exists(grc_filepath):
                        os.remove(grc_filepath)
                        print(f"Deleted: {grc_filepath}")
                    else:
                        print(f"File not found: {grc_filepath}")
                    
            elif table_name == "soi_data":
                pass  # Delete IQ files

            elif table_name == "triggers":
                # Use parameterized query to prevent SQL injection
                query = f"SELECT filename FROM {table_name} WHERE id = %s;"
                cur.execute(query, (row_id,))
                result = cur.fetchone()
                
                # If the row exists, fetch the filename, delete the file
                if result:
                    get_filename = result[0]
                    get_filepath = os.path.join(get_fg_library_dir(os_version), "Triggers", get_filename)
                    if os.path.exists(get_filepath):
                        os.remove(get_filepath)
                        print(f"Deleted: {get_filepath}")
                    else:
                        print(f"File not found: {get_filepath}")

            elif table_name == "attacks":
                # Use parameterized query to prevent SQL injection
                query = f"SELECT filename FROM {table_name} WHERE id = %s;"
                cur.execute(query, (row_id,))
                result = cur.fetchone()

                query = f"SELECT attack_type FROM {table_name} WHERE id = %s;"
                cur.execute(query, (row_id,))
                type_result = cur.fetchone()
                
                # If the row exists, fetch the filename, delete the file
                if result:
                    get_filename = result[0]
                    get_filepath = os.path.join(get_fg_library_dir(os_version), "Single-Stage Flow Graphs", get_filename)
                    if os.path.exists(get_filepath):
                        os.remove(get_filepath)
                        print(f"Deleted: {get_filepath}")
                    else:
                        print(f"File not found: {get_filepath}")
                    if type_result[0] == "Flow Graph":
                        grc_filepath = get_filepath.replace(".py",".grc")
                        if os.path.exists(grc_filepath):
                            os.remove(grc_filepath)
                            print(f"Deleted: {grc_filepath}")
                        else:
                            print(f"File not found: {grc_filepath}")

        # Use parameterized query to prevent SQL injection
        query = f"DELETE FROM {table_name} WHERE id = %s;"
        cur.execute(query, (row_id,))
        conn.commit()
        print(f"Row with ID {row_id} deleted from {table_name}.")

    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()  # Rollback in case of error
    finally:
        if cur is not None:
            cur.close()


def get_varchar_text_columns(conn, table_name):
    """
    Retrieves the names of columns in the specified table that are of type character varying or text.

    Parameters:
        conn: psycopg2 connection object.
        table_name (str): The name of the table to inspect.

    Returns:
        list: A list of column names that are of type character varying or text.
    """
    query = sql.SQL("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = %s
        AND data_type IN ('character varying', 'text');
    """)
    with conn.cursor() as cursor:
        cursor.execute(query, (table_name,))
        varchar_text_columns = [row[0] for row in cursor.fetchall()]
    return varchar_text_columns


def findMatchingRow(conn, table_name, provided_row):
    """
    Finds a matching row in a PostgreSQL table by comparing rows, ignoring the first column (ID) and jsonb columns.
    
    Parameters:
        conn: psycopg2 connection object to the PostgreSQL database.
        table_name (str): The name of the table to search.
        provided_row (list): The input row to match, with the first value (ID) ignored.
    
    Returns:
        int: The ID of the matching row, or None if no match is found.
    """
    try:
        # Get the list of character varying and text columns
        varchar_text_columns = get_varchar_text_columns(conn, table_name)
        
        with conn.cursor() as cursor:
            # Retrieve all rows from the table (ignoring the first column, ID)
            cursor.execute(sql.SQL("SELECT * FROM {}").format(sql.Identifier(table_name)))
            rows = cursor.fetchall()

            # Iterate through the rows and compare each row, skipping jsonb columns and the first column (ID)
            for row in rows:
                match = True
                # print(f"Comparing with row ID {row[0]}: {row}")  # Debug print for the current row
                
                for i, (column_name, value) in enumerate(zip(cursor.description, row)):
                    column_name = column_name.name
                    
                    # Skip the first column (ID) and excluded columns
                    if i == 0 or column_name not in varchar_text_columns:
                        continue
                    
                    # print(f"Column: {column_name}, Database Value: {value}, Provided Value: {provided_row[i]}")  # Debug print for values being compared
                    
                    # Extract provided value
                    provided_value = provided_row[i]
                    
                    # Handle None and 'None' explicitly
                    if value is None and (provided_value is None or provided_value == 'None'):
                        continue
                    if value is not None and str(value) != str(provided_value):
                        match = False
                        break
                
                if match:
                    # print(f"Found matching row with ID: {row[0]} in table: {table_name}")
                    return row[0]  # Return the ID of the matching row

            # print(f"No matching row found in table: {table_name}")
            return None

    except Exception as e:
        print(f"Error processing table {table_name}: {e}")
        return None


def removeProtocol(conn: connection, protocol_name: str, data_rates: float=None, median_packet_lengths: float=None) -> bool:
    """Remove protocol from `protocols` table

    Parameters
    ----------
    conn : connection
        Database connection
    protocol_name : str
        Protocol name

    Returns
    -------
    bool
        True if entries have been removed from the table, False if entries were not found in the table
    """
    cur = None
    result = False
    try:
        cur = conn.cursor()
        query = sql.SQL("DELETE FROM protocols WHERE protocol_name = '" + protocol_name + "' RETURNING *;")
        cur.execute(query)
        conn.commit()
        result = len(cur.fetchall()) > 0
    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()  # Rollback in case of error
    finally:
        if cur is not None:
            cur.close()
    return result


def removeModulationType(conn: connection, protocol: str, modulation_type: str) -> bool:
    """Remove protocol modulation type from `modulation_types` table

    Parameters
    ----------
    conn : connection
        Database connection
    protocol : str
        Protocol name
    modulation_type : str
        Modulation type

    Returns
    -------
    bool
        True if entries have been removed from the table, False if entries were not found in the table
    """
    cur = None
    result = False
    try:
        cur = conn.cursor()
        query = sql.SQL("DELETE FROM modulation_types WHERE protocol = %s AND modulation_type = %s RETURNING *;")
        cur.execute(query, (protocol, modulation_type))
        conn.commit()
        result = len(cur.fetchall()) > 0
    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()  # Rollback in case of error
    finally:
        if cur is not None:
            cur.close()
    return result


def removePacketType(conn: connection, protocol: str, packet_name: str, dissector: dict=None, fields: dict=None, sort_order: int=None) -> bool:
    """Remove packet type from `packet_types` table

    Parameters
    ----------
    conn : connection
        Database connection
    protocol : str
        Protocol name
    packet_name : str
        Packet name

    Returns
    -------
    bool
        True if entries have been removed from the table, False if entries were not found in the table
    """
    cur = None
    result = False
    try:
        cur = conn.cursor()
        query = sql.SQL("DELETE FROM packet_types WHERE protocol = %s AND packet_name = %s RETURNING *;")
        cur.execute(query, (protocol, packet_name))
        conn.commit()
        result = len(cur.fetchall()) > 0
    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()  # Rollback in case of error
    finally:
        if cur is not None:
            cur.close()
    return result


def removeSOI(conn: connection, protocol: str, soi_name: str, center_frequency: float=None, start_frequency: float=None, end_frequency: float=None, bandwidth: float=None, continuous: str=None, modulation: str=None, notes: str=None) -> bool:
    """Remove SOI from `soi_data` table

    Parameters
    ----------
    conn : connection
        Database connection
    protocol : str
        Protocol name
    soi_name : str
        SOI name

    Returns
    -------
    bool
        True if entries have been removed from the table, False if entries were not found in the table
    """
    cur = None
    result = False
    try:
        cur = conn.cursor()
        query = sql.SQL("DELETE FROM soi_data WHERE protocol = %s AND soi_name = %s RETURNING *;")
        cur.execute(query, (protocol, soi_name))
        conn.commit()
        result = len(cur.fetchall()) > 0
    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()  # Rollback in case of error
    finally:
        if cur is not None:
            cur.close()
    return result


def removeDemodulationFlowGraph(conn: connection, protocol: str, modulation_type: str=None, hardware: str=None, filename: str=None, output_type: str=None, version: str=None) -> bool:
    """Remove demodulation flow graph from `demodulation_flow_graphs` table

    Parameters
    ----------
    conn : connection
        Database connection
    protocol : str
        Protocol name
    filename : str
        Demod file name

    Returns
    -------
    bool
        True if entries have been removed from the table, False if entries were not found in the table
    """
    if filename is None:
        raise RuntimeError('`filename` must be a value other than None')

    cur = None
    result = False
    try:
        cur = conn.cursor()
        query = sql.SQL("DELETE FROM demodulation_flow_graphs WHERE protocol = %s AND filename = %s RETURNING *;")
        cur.execute(query, (protocol, filename))
        conn.commit()
        result = len(cur.fetchall()) > 0
    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()  # Rollback in case of error
    finally:
        if cur is not None:
            cur.close()
    return result


def removeAttack(conn: connection, protocol: str, attack_name: str=None, modulation_type: str=None, hardware: str=None, attack_type: str=None, filename: str=None, category_name: str=None, version: str=None) -> bool:
    """Remove attack from `attacks` table

    Parameters
    ----------
    conn : connection
        Database connection
    protocol : str
        Protocol name
    filename : str
        Attack file name

    Returns
    -------
    bool
        True if entries have been removed from the table, False if entries were not found in the table
    """
    if filename is None:
        raise RuntimeError('`filename` must be a value other than None')

    cur = None
    result = False
    try:
        cur = conn.cursor()
        query = sql.SQL("DELETE FROM attacks WHERE protocol = %s AND filename = %s RETURNING *;")
        cur.execute(query, (protocol, filename))
        conn.commit()
        result = len(cur.fetchall()) > 0
    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()  # Rollback in case of error
    finally:
        if cur is not None:
            cur.close()
    return result


# =============================================================
#                        OTHER Functions
# =============================================================
# This section contains other supporting functions for 
# interacting with the library. .
# =============================================================

def newField(fieldname="", defaultvalue="", length=0, sortorder=1, iscrc="False", crcrange=""):
    """
    Constructs a field dictionary for fields in stored in a packet type.
    """
    if not fieldname:
        fieldname = "New Field"
    if not length:
        length = len(defaultvalue)

    if iscrc == "True":
        iscrc = True
    else:
        iscrc = False

    if crcrange == "":
        new_field_subdict = {
            fieldname: {
                "Default Value": defaultvalue,
                "Length": int(length),
                "Sort Order": int(sortorder),
                "Is CRC": bool(iscrc),
            }
        }
    else:
        new_field_subdict = {
            fieldname: {
                "Default Value": defaultvalue,
                "Length": int(length),
                "Sort Order": int(sortorder),
                "Is CRC": bool(iscrc),
                "CRC Range": str(crcrange),
            }
        }
    return new_field_subdict



####################################################################################################
# These were copied over, check these two functions.
def SOI_AutoSelect(list1, SOI_priorities, SOI_filters):
    """
    Sort the SOI_list using specified criteria and choose the best SOI to examine.
    "priority" is a list specifying which list elements in the SOI_list will be sorted by.
    priority = (2, 0, 1) will produce a list that is sorted by element2, then element0, and then element1
    "must_contain" is a list containing elements that narrows the SOI list further by checking for matches after
    the SOI list is sorted by priority
    """

    # print('Unsorted list: {}' .format(list1))

    # Sort the list by element priority
    for x in reversed(range(0, len(SOI_priorities))):
        if SOI_filters[x] == "Highest":
            list1 = sorted(list1, key=lambda list1: float(list1[SOI_priorities[x]]), reverse=True)

        elif SOI_filters[x] == "Lowest":
            list1 = sorted(list1, key=lambda list1: float(list1[SOI_priorities[x]]), reverse=False)

        elif SOI_filters[x] == "Nearest to":
            # Take Absolute Value of Value Differences and then Sort
            new_list_matching = []
            abs_value_list = []

            # Absolute Value
            for soi in range(0, len(list1)):
                abs_value_list.append(abs(float(SOI_parameters[x]) - float(list1[soi][SOI_priorities[x]])))

            # Sort from Absolute Value
            sorted_index = sorted(range(len(abs_value_list)), key=lambda x: abs_value_list[x])
            for index in range(0, len(sorted_index)):
                new_list_matching.append(list1[sorted_index[index]])
            list1 = new_list_matching

        elif SOI_filters[x] == "Greater than":
            # Keep Things that Fit Criteria
            new_list_matching = []
            for soi in range(0, len(list1)):
                if float(list1[soi][SOI_priorities[x]]) > float(SOI_parameters[x]):
                    new_list_matching.append(list1[soi])
            list1 = new_list_matching

        elif SOI_filters[x] == "Less than":
            # Keep Things that Fit Criteria
            new_list_matching = []
            for soi in range(0, len(list1)):
                if float(list1[soi][SOI_priorities[x]]) < float(SOI_parameters[x]):
                    new_list_matching.append(list1[soi])
            list1 = new_list_matching

        elif SOI_filters[x] == "Containing":
            # Keep Things that Fit Criteria
            new_list_matching = []
            for soi in range(0, len(list1)):
                if list1[soi][0] in SOI_parameters[x]:
                    new_list_matching.append(list1[soi])
            list1 = new_list_matching

    # print('Sorted list: {}' .format(list1))

    # Check if the list is empty
    if len(list1) > 0:
        soi = list1[0]
    else:
        print("No SOI Matches the Criteria")
        soi = []

    print("Selected SOI: {}".format(soi))

    return soi


def SOI_LibraryCheck(soi):
    """Look up the SOI to recommend a best-fit flow graph from the library"""

    # There needs to be some kind of look up to limit the possibilities
    # What parameters will be used to search the library? Modulation, Spreading, Frequency, Bandwidth?
    #  How will the search library be managed?

    # (
    #   Modulation_Type, Modulation_Sub_Parameters, Same_Modulation_Type_Index
    # ) : (
    #   Flow_Graph_Name, [Default_Variables], [Default_Values], [Potential_Attacks]
    # )

    # Find Flow Graphs with Same Modulation Type
    same_modulation_list_names = [
        v[0] for k, v in SOI_library.items() if k[0] == soi[0]
    ]  # Look Through Each Key in the Search Dictionary
    if not same_modulation_list_names:
        same_modulation_list_names = [v[0] for v in SOI_library.values()]

    return same_modulation_list_names


###################################


if __name__ == "__main__":
    pass
