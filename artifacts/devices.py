"""Persisted Bluetooth metadata, distinct from live device presence."""
import configparser
import re
from pathlib import Path

from artifacts.parser_support import check_cancelled, entry


def usb_event(message):
    match = re.search(r'\busb ([\d.-]+): (.*)', message, re.IGNORECASE)
    if match and re.search(r'new .*USB device|USB disconnect|New USB device found|SerialNumber:|Product:|Manufacturer:', match[2], re.IGNORECASE):
        message = match[2]
        action = ('disconnect' if re.search(r'USB disconnect', message, re.I) else
                  'connect' if re.search(r'new .*USB device.*(?:using|number)', message, re.I) else 'descriptor')
        values = {}
        for name, pattern in (('idVendor', r'idVendor=([0-9a-f]{4})'), ('idProduct', r'idProduct=([0-9a-f]{4})'),
                              ('device_number', r'device number (\d+)'), ('serial', r'SerialNumber:\s*(.*)'),
                              ('product', r'Product:\s*(.*)'), ('manufacturer', r'Manufacturer:\s*(.*)')):
            value = re.search(pattern, message, re.I)
            if value:
                values[name] = int(value[1]) if name == 'device_number' else value[1].strip()
        return dict(bus_path=match[1], device_message=message, action=action, **values,
                    action_semantics='Kernel USB announcement/descriptor; enumeration success and physical actor are not established by this message alone',
                    session_scope='Historical log event; relation to last logon not established')
    return None


def bluetooth(data, path, cancelled):
    document = configparser.ConfigParser(interpolation=None, strict=False)
    document.optionxform = str
    document.read_string(data.decode('utf-8', errors='replace'))
    parts = Path(path).parts
    for section in document.sections():
        check_cancelled(cancelled)
        yield entry('bluetooth_stored_device', section, adapter_address=parts[-3],
                    device_address=parts[-2], section=section, fields=dict(document[section]),
                    connection_semantics='Stored configuration/association, not proof of current connection or connection since last logon')
