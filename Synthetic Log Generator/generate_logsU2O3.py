import random
from datetime import datetime, timedelta
import collections

# --- Config ---
TARGET_LOG_ENTRIES = 2000
DENY_DROP_PROBABILITY = 0.99
USER_FILE = "abac_user.txt"
OBJECT_FILE = "abac_object.txt"
LOG_FILE = "abac_logs.txt"

# --- Attribute spaces ---
DEPARTMENTS = {
    "Finance": ["Analyst", "Manager"],
    "Sales": ["Representative", "Manager"],
    "IT": ["Support_Specialist", "System_Admin"],
    "HR": ["Generalist", "Manager"],
}
OBJECTS_STRUCTURE = {
    "Financial": ["Low", "Medium", "High"],
    "Operational": ["Low", "Medium"],
    "System": ["Medium", "High"],
    "HR": ["Medium", "High"],
}
ACTIONS = ["read", "write", "execute"]
FIRST_NAMES = ["Alex", "Jordan", "Taylor", "Morgan"]
REGIONS = ["AMER", "EMEA", "APAC"]

def get_decision(user, obj, action):
    u_dept, u_desig = user["department"], user["designation"]
    o_type, o_sens, o_reg = obj["type"], obj["sensitivity"], obj["region"]

    # Region gating for High reads across depts; IT bypass allowed
    if action == "read" and o_sens == "High" and u_dept != o_type and u_dept != "IT":
        domain_region = {
            "Financial": "AMER",
            "HR": "EMEA",
            "System": "APAC",
            "Operational": "AMER",
        }.get(o_type, "AMER")
        if o_reg != domain_region:
            return "Deny"

    # Dept-aligned access
    if u_dept == o_type and action in ["read", "write"]:
        if o_sens == "High" and action == "write" and u_desig != "Manager":
            return "Deny"
        return "Allow"

    # Cross-functional allowances
    if u_dept == "IT" and action == "read":
        return "Allow"

    return "Deny"

def generate_users():
    users = []
    for dept, roles in DEPARTMENTS.items():
        for i in range(len(roles) * 6):
            users.append({
                "user_name": f"{random.choice(FIRST_NAMES).lower()}_{dept.lower()}_{i}",
                "department": dept,
                "designation": random.choice(roles),
            })
    return users

def generate_objects():
    objects = []
    file_ext = {"Financial": "xlsx", "Operational": "csv", "System": "sh", "HR": "pdf"}
    for o_type, sens_list in OBJECTS_STRUCTURE.items():
        for sens in sens_list:
            for i in range(6):
                objects.append({
                    "object_name": f"{o_type.lower()}_{sens.lower()}_{i}.{file_ext[o_type]}",
                    "type": o_type,
                    "sensitivity": sens,
                    "region": random.choice(REGIONS),
                })
    return objects

def format_for_file(entity, is_user=True):
    if is_user:
        return f"<{entity['user_name']} department:{entity['department']} designation:{entity['designation']}>"
    else:
        return f"<{entity['object_name']} type:{entity['type']} sensitivity:{entity['sensitivity']} region:{entity['region']}>"

def main():
    users, objects = generate_users(), generate_objects()
    with open(USER_FILE, "w") as f: f.write("\n".join(format_for_file(u, True) for u in users))
    with open(OBJECT_FILE, "w") as f: f.write("\n".join(format_for_file(o, False) for o in objects))

    generated_logs, attempts = [], 0
    start_time = datetime.now() - timedelta(hours=12)

    while len(generated_logs) < TARGET_LOG_ENTRIES:
        attempts += 1
        user, obj, action = random.choice(users), random.choice(objects), random.choice(ACTIONS)
        decision = get_decision(user, obj, action)
        if decision == "Allow" or (decision == "Deny" and random.random() < (1 - DENY_DROP_PROBABILITY)):
            t = (start_time + timedelta(seconds=attempts * random.randint(5, 25))).strftime("%H:%M:%S")
            generated_logs.append(f"<{user['user_name']} {obj['object_name']} {action} {t} {decision}>")

    with open(LOG_FILE, "w") as f: f.write("\n".join(generated_logs))

    counts = collections.Counter(log.split()[-1].rstrip(">") for log in generated_logs)
    allow_count, deny_count = counts.get("Allow", 0), counts.get("Deny", 0)
    total = max(allow_count + deny_count, 1)
    print(f"U2/O3 -> Final Log Ratio: {allow_count} Allow ({allow_count/total:.1%}) | {deny_count} Deny ({deny_count/total:.1%})")

if __name__ == "__main__":
    main()
