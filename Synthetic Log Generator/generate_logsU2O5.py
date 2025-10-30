
import random
from datetime import datetime, timedelta
import collections

# --- Config ---
TARGET_LOG_ENTRIES = 100
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
PROJECTS = ["alpha", "beta", "gamma"]

# Map departments to their primary regions for object generation
DEPT_REGIONS = {"Finance": "AMER", "Sales": "AMER", "IT": "APAC", "HR": "EMEA"}

def get_decision(user, obj, action):
    """Schema-aware decision with 2 user attrs, 4 object attrs."""
    # Unpack user attributes
    u_dept = user.get("department")
    u_desig = user.get("designation")
    
    # Unpack all object attributes
    o_type = obj.get("type")
    o_sens = obj.get("sensitivity")
    o_reg = obj.get("region")
    o_proj = obj.get("project")
    o_owner = obj.get("owner_dept")
    
    # Rule 1: Department-aligned access (base rule)
    if u_dept == o_type and action in ["read", "write"]:
        # High sensitivity requires Manager designation
        if o_sens == "High" and action == "write" and u_desig != "Manager":
            return "Deny"
        return "Allow"
    
    # Rule 2: IT can read everything
    if u_dept == "IT" and action == "read":
        return "Allow"
    
    # Rule 3: Regional access for Low sensitivity (relaxed collaboration)
    if action == "read" and o_sens == "Low":
        dept_region = DEPT_REGIONS.get(u_dept, "AMER")
        if dept_region == o_reg:
            return "Allow"
    
    # Rule 4: Cross-department Low read (global collaboration)
    if action == "read" and o_sens == "Low":
        return "Allow"
    
    # Rule 5: Manager override - Managers can read Medium from any department
    if u_desig == "Manager" and action == "read" and o_sens == "Medium":
        return "Allow"
    
    # Rule 6: Finance can read Operational data
    if u_dept == "Finance" and o_type == "Operational" and action == "read":
        if o_sens in ["Low", "Medium"]:
            return "Allow"
    
    # Rule 7: Sales managers can read Financial Low/Medium
    if u_dept == "Sales" and u_desig == "Manager" and o_type == "Financial":
        if action == "read" and o_sens in ["Low", "Medium"]:
            return "Allow"
    
    # Rule 8: HR can read Medium sensitivity
    if u_dept == "HR" and action == "read" and o_sens == "Medium":
        return "Allow"
    
    # Rule 9: Owner-department matching (write access for Medium if owned)
    if u_dept == o_owner and action == "write" and o_sens == "Medium":
        return "Allow"
    
    # Rule 10: Same-region High read for Managers
    if u_desig == "Manager" and action == "read" and o_sens == "High":
        dept_region = DEPT_REGIONS.get(u_dept, "AMER")
        if dept_region == o_reg:
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
                # Assign owner_dept to match type most of the time for realistic ownership
                owner = o_type if random.random() < 0.7 else random.choice(list(DEPARTMENTS.keys()))
                
                objects.append({
                    "object_name": f"{o_type.lower()}_{sens.lower()}_{i}.{file_ext[o_type]}",
                    "type": o_type,
                    "sensitivity": sens,
                    "region": random.choice(REGIONS),
                    "project": random.choice(PROJECTS),
                    "owner_dept": owner,
                })
    return objects

def format_for_file(entity, is_user=True):
    if is_user:
        return f"<{entity['user_name']} department:{entity['department']} designation:{entity['designation']}>"
    else:
        return f"<{entity['object_name']} type:{entity['type']} sensitivity:{entity['sensitivity']} region:{entity['region']} project:{entity['project']} owner_dept:{entity['owner_dept']}>"

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
    print(f"U2/O4 -> Final Log Ratio: {allow_count} Allow ({allow_count/total:.1%}) | {deny_count} Deny ({deny_count/total:.1%})")
    print(f"Generated {len(users)} users, {len(objects)} objects, {len(generated_logs)} log entries")

if __name__ == "__main__":
    main()
