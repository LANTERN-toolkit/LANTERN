# /app/utils.py
import re

def parse_user_data(data_string: str) -> list[dict]:
    """Parses the custom user data format into a list of dictionaries."""
    parsed_list = []
    pattern = re.compile(r'<(\w+)\s+department:(\S+)\s+designation:(.*)>')
    for line in data_string.strip().split('\n'):
        match = pattern.search(line)
        if match:
            # BUG FIX: Added .strip() to remove trailing whitespace from the designation
            parsed_list.append({
                'user_name': match.group(1).strip(),
                'department': match.group(2).strip(),
                'designation': match.group(3).strip()
            })
    return parsed_list

def parse_object_data(data_string: str) -> list[dict]:
    """Parses the custom object data format into a list of dictionaries."""
    parsed_list = []
    pattern = re.compile(r'<(\S+)\s+type:(\S+)\s+sensitivity:(\S+)>')
    for line in data_string.strip().split('\n'):
        match = pattern.search(line)
        if match:
            parsed_list.append({
                'object_name': match.group(1).strip(),
                'type': match.group(2).strip(),
                'sensitivity': match.group(3).strip()
            })
    return parsed_list

def parse_log_data(data_string: str) -> list[dict]:
    """Parses the custom log format into a list of dictionaries, ignoring the timestamp."""
    parsed_list = []
    for line in data_string.strip().split('\n'):
        if not line.strip():
            continue
        cleaned_line = line.strip()[1:-1]
        parts = cleaned_line.split()
        if len(parts) == 5:
            log_entry = {
                'user_name': parts[0],
                'object_name': parts[1],
                'action': parts[2],
                'decision': parts[4]
            }
            parsed_list.append(log_entry)
    return parsed_list