#!/usr/bin/env python3
"""Validate/import packet format JSON to FISSURE PostgreSQL via existing .env.

Usage from repository root:
    python3 Tools/import_packet_formats.py definitions/tpms_...json
    python3 Tools/import_packet_formats.py definitions/tpms_...json --apply

Default mode performs offline validation only. --apply writes to PostgreSQL.
A changed existing definition MUST increment its revision. The importer does
not add or replace packet_types rows, and does not touch captured observations.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'fissure' / 'utils'))
from protocol_packet_formats import validate_format_record  # noqa: E402


def _load_environment():
    from dotenv import load_dotenv
    load_dotenv(ROOT / '.env')
    return dict(
        dbname=os.environ.get('POSTGRES_DB'),
        user=os.environ.get('POSTGRES_USER'),
        password=os.environ.get('POSTGRES_PASSWORD'),
        host=os.environ.get('POSTGRES_HOST', 'localhost'),
        port=os.environ.get('POSTGRES_EXTERNAL_PORT', '5431'),
    )


def _digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode('utf-8')).hexdigest()


def _apply(record):
    import psycopg2
    from psycopg2.extras import Json

    connection = psycopg2.connect(**_load_environment())
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT to_regclass('public.packet_formats')")
                if cursor.fetchone()[0] is None:
                    raise RuntimeError('packet_formats table is missing; apply the SQL migration first')
                cursor.execute('''
                    SELECT revision, definition FROM public.packet_formats
                    WHERE format_key = %s FOR UPDATE
                ''', (record['format_key'],))
                existing = cursor.fetchone()
                if existing:
                    revision, definition = existing
                    if record['revision'] < revision:
                        raise ValueError('refusing to downgrade an existing format revision')
                    if record['revision'] == revision:
                        # Equal revision only permits a strictly identical record.
                        cursor.execute('''
                            SELECT protocol_name, format_name, enabled,
                                   validation_status, reference, notes
                            FROM public.packet_formats WHERE format_key = %s
                        ''', (record['format_key'],))
                        saved = cursor.fetchone()
                        intended = (record['protocol_name'], record['format_name'],
                                    record['enabled'], record['validation_status'],
                                    record.get('reference'), record.get('notes'))
                        if _digest(definition) == _digest(record['definition']) and saved == intended:
                            print('Already installed (same revision and content).')
                            return
                        raise ValueError('format changed without a revision increment')
                protocol_name = record.get('protocol_link_name') or record['protocol_name']
                cursor.execute('SELECT id FROM public.protocols WHERE protocol_name = %s',
                               (protocol_name,))
                row = cursor.fetchone()
                protocol_id = row[0] if row else None
                packet_type_id = None
                if record.get('packet_type_link_name'):
                    cursor.execute('''
                        SELECT id FROM public.packet_types
                        WHERE protocol = %s AND packet_name = %s ORDER BY id LIMIT 1
                    ''', (protocol_name, record['packet_type_link_name']))
                    row = cursor.fetchone()
                    packet_type_id = row[0] if row else None
                cursor.execute('''
                    INSERT INTO public.packet_formats
                        (format_key, protocol_name, format_name, protocol_id, packet_type_id,
                         revision, schema_version, enabled, validation_status,
                         definition, reference, notes)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (format_key) DO UPDATE SET
                        protocol_name = EXCLUDED.protocol_name,
                        format_name = EXCLUDED.format_name,
                        protocol_id = EXCLUDED.protocol_id,
                        packet_type_id = EXCLUDED.packet_type_id,
                        revision = EXCLUDED.revision,
                        schema_version = EXCLUDED.schema_version,
                        enabled = EXCLUDED.enabled,
                        validation_status = EXCLUDED.validation_status,
                        definition = EXCLUDED.definition,
                        reference = EXCLUDED.reference,
                        notes = EXCLUDED.notes
                ''', (record['format_key'], record['protocol_name'], record['format_name'],
                      protocol_id, packet_type_id, record['revision'],
                      record['schema_version'], record['enabled'], record['validation_status'],
                      Json(record['definition']), record.get('reference'), record.get('notes')))
        print(f"Saved {record['format_key']} revision {record['revision']}. "
              'Refresh the FISSURE Library cache before analyzing.')
        if protocol_id is None:
            print('Note: no existing Library protocol ID linked; format still works independently.')
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('files', metavar='DEFINITION.json', nargs='+', type=Path)
    parser.add_argument('--apply', action='store_true', help='Write validated definitions to PostgreSQL')
    args = parser.parse_args()
    records = []
    for file_path in args.files:
        record = json.loads(file_path.read_text(encoding='utf-8'))
        validate_format_record(record)
        print(f"Validated {record['format_key']} revision {record['revision']} "
              f"({record['validation_status']}); SHA-256 {_digest(record['definition'])}")
        records.append(record)
    if not args.apply:
        print('Validation only. Re-run with --apply to write to PostgreSQL.')
        return
    for record in records:
        _apply(record)


if __name__ == '__main__':
    main()
