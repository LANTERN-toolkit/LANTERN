# import random
# from datetime import datetime, timedelta
# import collections

# # --- Configuration ---
# TARGET_LOG_ENTRIES = 1200
# DENY_DROP_PROBABILITY = 0.998

# USER_FILE = "abac_user.txt"
# OBJECT_FILE = "abac_object.txt"
# LOG_FILE = "abac_logs.txt"

# # --- 1. Define Data Structures ---

# DEPARTMENTS = {
#     "Finance": ["Analyst", "Senior_Analyst", "Manager", "Director"],
#     "Sales": ["Representative", "Senior_Representative", "Manager", "Director"],
#     "IT": ["Support_Specialist", "System_Admin", "Network_Engineer", "IT_Manager"],
#     "HR": ["Generalist", "Recruiter", "HR_Manager", "Director"],
#     "Engineering": ["Software_Engineer", "Senior_Engineer", "Lead_Engineer", "Engineering_Manager"],
#     "Marketing": ["Coordinator", "Specialist", "Marketing_Manager", "Director"],
#     "Legal": ["Paralegal", "Analyst", "General_Counsel", "Chief_Legal_Officer"],
#     "Operations": ["Coordinator", "Operations_Manager", "Director_of_Operations"],
#     "Customer_Support": ["Agent", "Team_Lead", "Support_Manager"],
#     "Research": ["Researcher", "Senior_Researcher", "Lead_Scientist"]
# }

# OBJECTS_STRUCTURE = {
#     "Financial": ["Low", "Medium", "High"], "Operational": ["Low", "Medium"],
#     "System": ["Medium", "High"], "HR": ["Medium", "High", "Confidential"],
#     "Source_Code": ["Medium", "High"], "Legal": ["Medium", "High", "Confidential"],
#     "Marketing": ["Low", "Medium"], "Customer_Data": ["High", "Confidential"], "General": ["Low"]
# }

# ACTIONS = ["read", "write", "execute", "delete"]
# FIRST_NAMES = ["Ananya", "Vikram", "Priya", "Arjun", "Meera", "Rohan", "Saanvi", "Kabir", "Zara", "Ishaan"]

# # --- NEW: Define additional attributes for both users and resources ---
# LOCATIONS = ['NewYork', 'London', 'Singapore', 'Remote']
# PROJECTS = ['alpha', 'beta', 'gamma', 'delta']
# REGIONS = ['AMER', 'EMEA', 'APAC'] # New resource attribute

# # --- NEW: Define realistic correlations for attribute generation ---
# PROJECT_ASSIGNMENTS = {"Engineering": ["alpha", "beta"], "IT": ["alpha", "delta"], "Finance": ["gamma"], "Sales": ["beta"], "Marketing": ["beta"]}
# # --- NEW: Map user locations to resource regions ---
# LOCATION_TO_REGION = {'NewYork': 'AMER', 'London': 'EMEA', 'Singapore': 'APAC', 'Remote': 'AMER'}
# DATA_REGION_MAP = {"Financial": "AMER", "Legal": "AMER", "HR": "EMEA", "Customer_Data": "EMEA", "Source_Code": "APAC"}

# # Map object types to their owning departments so project assignments can be resolved.
# OWNING_DEPARTMENT = {
#     "Financial": "Finance",
#     "Operational": "Operations",
#     "System": "IT",
#     "HR": "HR",
#     "Source_Code": "Engineering",
#     "Legal": "Legal",
#     "Marketing": "Marketing",
#     "Customer_Data": "Customer_Support",
#     "General": "Operations"
# }


# # --- 2. Highly Elaborated, Deterministic Rule-Based Decision Logic ---

# def get_decision(user, obj, action):
#     # --- UPDATED: Unpack all attributes ---
#     u_dept, u_desig, u_clearance = user['department'], user['designation'], user['clearance_level']
#     u_loc, u_proj = user['location'], user['project_id']
#     o_type, o_sens, o_reg = obj['type'], obj['sensitivity'], obj['region']
#     o_proj = obj['project_id']

#     # --- NEW: High-precedence Constraint Rule (Project-based access) ---
#     if u_proj != o_proj and u_dept not in ['IT', 'Legal', 'Finance']:
#         return "Deny"

#     # --- NEW: High-precedence Data Residency Rule (GDPR-like) ---
#     # A user's region (derived from location) must match the data's region for sensitive data.
#     user_region = LOCATION_TO_REGION.get(u_loc)
#     if user_region != o_reg and o_sens in ['High', 'Confidential']:
#         # Exception: IT admins and Legal Counsel can access data globally for support/auditing
#         if not (u_dept == 'IT' and u_desig == 'IT_Manager') and not (u_dept == 'Legal'):
#             return "Deny"

#     # --- GLOBAL RULES ---
#     if o_sens == 'Confidential':
#         if u_clearance != 'secret': return "Deny"
#         return "Allow" if u_desig in ['Director', 'Chief_Legal_Officer'] and u_dept == o_type and action == 'read' else "Deny"

#     # --- DEPARTMENT-SPECIFIC RULES ---
#     if u_dept == o_type:
#         if u_dept == 'Finance':
#             if action in ['read', 'write']:
#                 if o_sens == 'High' and u_desig in ['Manager', 'Director'] and u_clearance == 'secret': return "Allow"
#                 if o_sens in ['Low', 'Medium'] and u_clearance in ['internal', 'secret']: return "Allow"
        
#         elif u_dept == 'Engineering':
#              if action == 'write' and u_clearance in ['internal', 'secret'] and u_proj == o_proj:
#                  return "Allow"
        
#         elif u_dept in ['HR', 'Sales', 'Marketing'] and action in ['read', 'write']:
#             if u_clearance in ['internal', 'secret']: return "Allow"

#     # --- CROSS-FUNCTIONAL RULES ---
#     if u_dept == 'IT' and action == 'read' and u_clearance in ['internal', 'secret']:
#         return "Allow"
        
#     if o_type == 'General' and o_sens == 'Low' and action == 'read':
#         return "Allow"
        
#     return "Deny"

# # --- 3. Data Generation Functions ---

# def generate_users():
#     # --- UPDATED: Generates users with all attributes ---
#     users = []
#     for dept, designations in DEPARTMENTS.items():
#         for i in range(len(designations) * 2):
#             user_name = f"{random.choice(FIRST_NAMES).lower()}_{dept.lower()}_{i}"
#             designation = random.choice(designations)
#             clearance = 'internal'
#             if dept in ['Legal', 'Finance'] and designation in ['Director', 'Manager', 'Chief_Legal_Officer']: clearance = 'secret'
#             elif designation in ['Director', 'Engineering_Manager']: clearance = 'secret'
#             users.append({
#                 "user_name": user_name, "department": dept, "designation": designation,
#                 "clearance_level": clearance,
#                 "location": random.choice(LOCATIONS),
#                 "project_id": random.choice(PROJECT_ASSIGNMENTS.get(dept, PROJECTS))
#             })
#     return users

# def generate_objects():
#     # --- UPDATED: Generates objects with all attributes ---
#     objects = []
#     file_ext = {"Financial": "xlsx", "Operational": "csv", "System": "sh", "HR": "pdf", "Source_Code": "py", "Legal": "pdf", "Marketing": "pptx", "Customer_Data": "db", "General": "pdf"}
#     for o_type, sensitivities in OBJECTS_STRUCTURE.items():
#         for sens in sensitivities:
#             for i in range(3):
#                 project = random.choice(PROJECT_ASSIGNMENTS.get(OWNING_DEPARTMENT.get(o_type, "IT"), PROJECTS))
#                 region = DATA_REGION_MAP.get(o_type, "AMER") # Assign region based on data type

#                 objects.append({
#                     "object_name": f"{o_type.lower()}_{sens.lower()}_{i}.{file_ext[o_type]}", 
#                     "type": o_type, "sensitivity": sens,
#                     "project_id": project,
#                     "region": region
#                 })
#     return objects

# def format_for_file(entity, is_user=True):
#     # --- UPDATED: Formats all attributes for the output file ---
#     if is_user:
#         return (f"<{entity['user_name']} department:{entity['department']} designation:{entity['designation']} "
#                 f"clearance_level:{entity['clearance_level']} location:{entity['location']} project_id:{entity['project_id']}>")
#     else:
#         return (f"<{entity['object_name']} type:{entity['type']} sensitivity:{entity['sensitivity']} "
#                 f"project_id:{entity['project_id']} region:{entity['region']}>")
# # --- 4. Main Script Execution with Probabilistic Loop ---
# def main():
#     # ... (The main function remains the same) ...
#     print("--- Starting Log Generation with Probabilistic Control ---")
#     all_users, all_objects = generate_users(), generate_objects()
#     print(f"Generating {USER_FILE} with {len(all_users)} users...")
#     with open(USER_FILE, "w") as f: f.write("\n".join([format_for_file(u) for u in all_users]))
#     print(f"Generating {OBJECT_FILE} with {len(all_objects)} objects...")
#     with open(OBJECT_FILE, "w") as f: f.write("\n".join([format_for_file(o, is_user=False) for o in all_objects]))
    
#     print(f"Generating logs to reach a target of {TARGET_LOG_ENTRIES} entries...")
#     generated_logs, attempts = [], 0
#     start_time = datetime.now() - timedelta(hours=12)
    
#     while len(generated_logs) < TARGET_LOG_ENTRIES:
#         attempts += 1
#         user, obj, action = random.choice(all_users), random.choice(all_objects), random.choice(ACTIONS)
#         decision = get_decision(user, obj, action)
        
#         if decision == "Allow" or (decision == "Deny" and random.random() < (1 - DENY_DROP_PROBABILITY)):
#             time_str = (start_time + timedelta(seconds=attempts * random.randint(5, 30))).strftime("%H:%M:%S")
#             generated_logs.append(f"<{user['user_name']} {obj['object_name']} {action} {time_str} {decision}>")
    
#     print(f"\nWriting {len(generated_logs)} logs to {LOG_FILE} (took {attempts} generation attempts).")
#     with open(LOG_FILE, "w") as f: f.write("\n".join(generated_logs))
        
#     decision_counts = collections.Counter(log.split()[-1].replace('>', '') for log in generated_logs)
#     allow_count = decision_counts.get('Allow', 0)
#     deny_count = decision_counts.get('Deny', 0)
#     total_count = allow_count + deny_count or 1
    
#     print("\n--- Generation Complete! ---")
#     print(f"Final Log Ratio: {allow_count} Allow ({allow_count/total_count:.1%}) | {deny_count} Deny ({deny_count/total_count:.1%})")

# if __name__ == "__main__":
#     main()
# import random
# from datetime import datetime, timedelta
# import collections

# # --- Configuration ---
# TARGET_LOG_ENTRIES = 1200
# DENY_DROP_PROBABILITY = 0.99 

# # --- NEW: Changed filenames for this simplified dataset ---
# USER_FILE = "abac_user.txt"
# OBJECT_FILE = "abac_object.txt"
# LOG_FILE = "abac_logs.txt"

# # --- 1. Define Data Structures ---

# DEPARTMENTS = {
#     "Finance": ["Analyst", "Manager"],
#     "Sales": ["Representative", "Manager"],
#     "IT": ["Support_Specialist", "System_Admin"],
#     "HR": ["Generalist", "Manager"],
# }

# OBJECTS_STRUCTURE = {
#     "Financial": ["Low", "Medium", "High"],
#     "Operational": ["Low", "Medium"],
#     "System": ["Medium", "High"],
#     "HR": ["Medium", "High"],
#     "General": ["Low"],
# }

# ACTIONS = ["read", "write", "execute"]
# FIRST_NAMES = ["Alex", "Jordan", "Taylor", "Morgan"]
# REGIONS = ['AMER', 'EMEA', 'APAC']

# # --- 2. Simplified, Deterministic Rule-Based Decision Logic ---

# def get_decision(user, obj, action):
#     """
#     This function contains rules based on the simplified attribute set.
#     """
#     # --- UPDATED: Unpack simplified attributes ---
#     u_dept, u_desig = user['department'], user['designation']
#     o_type, o_sens, o_reg = obj['type'], obj['sensitivity'], obj['region']

#     # --- High-precedence Data Residency Rule ---
#     # EMEA data can only be accessed by IT.
#     if o_reg == 'EMEA' and u_dept != 'IT':
#         return "Deny"

#     # --- Department-Specific Rules ---
#     # Users can generally read/write data that matches their department.
#     if u_dept == o_type and action in ['read', 'write']:
#         # But only managers can write to High sensitivity data.
#         if o_sens == 'High' and action == 'write' and u_desig != 'Manager':
#             return "Deny"
#         return "Allow"

#     # --- Cross-Functional Rules ---
#     # IT can read anything that isn't from EMEA (already handled)
#     if u_dept == 'IT' and action == 'read':
#         return "Allow"
    
#     # Sales Managers can read Low sensitivity Financial data.
#     if u_dept == 'Sales' and u_desig == 'Manager' and o_type == 'Financial' and o_sens == 'Low' and action == 'read':
#         return "Allow"
        
#     # All users can read General documents.
#     if o_type == 'General' and action == 'read':
#         return "Allow"
        
#     return "Deny"

# # --- 3. Data Generation Functions ---

# def generate_users():
#     # --- UPDATED: Generates users with only 2 attributes ---
#     users = []
#     for dept, designations in DEPARTMENTS.items():
#         for i in range(len(designations) * 5): # Create more users per role
#             user_name = f"{random.choice(FIRST_NAMES).lower()}_{dept.lower()}_{i}"
#             users.append({
#                 "user_name": user_name, 
#                 "department": dept, 
#                 "designation": random.choice(designations),
#             })
#     return users

# def generate_objects():
#     # --- UPDATED: Generates objects with only 3 attributes ---
#     objects = []
#     file_ext = {"Financial": "xlsx", "Operational": "csv", "System": "sh", "HR": "pdf", "General": "pdf"}
#     for o_type, sensitivities in OBJECTS_STRUCTURE.items():
#         for sens in sensitivities:
#             for i in range(5): # Create more objects
#                 objects.append({
#                     "object_name": f"{o_type.lower()}_{sens.lower()}_{i}.{file_ext[o_type]}", 
#                     "type": o_type, 
#                     "sensitivity": sens,
#                     "region": random.choice(REGIONS)
#                 })
#     return objects

# def format_for_file(entity, is_user=True):
#     # --- UPDATED: Formats the simplified attributes ---
#     if is_user:
#         return f"<{entity['user_name']} department:{entity['department']} designation:{entity['designation']}>"
#     else:
#         return f"<{entity['object_name']} type:{entity['type']} sensitivity:{entity['sensitivity']} region:{entity['region']}>"

# # --- 4. Main Script Execution with Probabilistic Loop ---
# def main():
#     print("--- Starting SIMPLIFIED Log Generation (2 User Attrs, 3 Resource Attrs) ---")
#     all_users, all_objects = generate_users(), generate_objects()
#     print(f"Generating {USER_FILE} with {len(all_users)} users and {len(all_objects)} objects.")
    
#     with open(USER_FILE, "w") as f: f.write("\n".join([format_for_file(u) for u in all_users]))
#     with open(OBJECT_FILE, "w") as f: f.write("\n".join([format_for_file(o, is_user=False) for o in all_objects]))
    
#     print(f"Generating logs to reach a target of {TARGET_LOG_ENTRIES} entries...")
#     generated_logs, attempts = [], 0
#     start_time = datetime.now() - timedelta(hours=12)
    
#     while len(generated_logs) < TARGET_LOG_ENTRIES:
#         attempts += 1
#         user, obj, action = random.choice(all_users), random.choice(all_objects), random.choice(ACTIONS)
#         decision = get_decision(user, obj, action)
        
#         if decision == "Allow" or (decision == "Deny" and random.random() < (1 - DENY_DROP_PROBABILITY)):
#             time_str = (start_time + timedelta(seconds=attempts * random.randint(5, 30))).strftime("%H:%M:%S")
#             generated_logs.append(f"<{user['user_name']} {obj['object_name']} {action} {time_str} {decision}>")
    
#     print(f"\nWriting {len(generated_logs)} logs to {LOG_FILE} (took {attempts} generation attempts).")
#     with open(LOG_FILE, "w") as f: f.write("\n".join(generated_logs))
        
#     decision_counts = collections.Counter(log.split()[-1].replace('>', '') for log in generated_logs)
#     allow_count = decision_counts.get('Allow', 0)
#     deny_count = decision_counts.get('Deny', 0)
#     total_count = allow_count + deny_count or 1
    
#     print("\n--- Generation Complete! ---")
#     print(f"Final Log Ratio: {allow_count} Allow ({allow_count/total_count:.1%}) | {deny_count} Deny ({deny_count/total_count:.1%})")

# if __name__ == "__main__":
#     main()

import random
from datetime import datetime, timedelta
import collections

# --- Configuration ---
TARGET_LOG_ENTRIES =800
DENY_DROP_PROBABILITY = 0.99 

USER_FILE = "abac_user.txt"
OBJECT_FILE = "abac_object.txt"
LOG_FILE = "abac_logs.txt"

# --- 1. Define Data Structures ---
DEPARTMENTS = {"Finance": ["Analyst", "Manager"], "Sales": ["Representative", "Manager"], "IT": ["Support_Specialist", "System_Admin"], "HR": ["Generalist", "Manager"]}
OBJECTS_STRUCTURE = {"Financial": ["Low", "Medium"], "Operational": ["Low", "Medium"], "System": ["Medium", "High"], "General": ["Low"]}
ACTIONS = ["read", "write", "execute"]
FIRST_NAMES = ["Alex", "Jordan", "Taylor", "Morgan"]
REGIONS = ['AMER', 'EMEA', 'APAC']
# --- NEW: Added Project attribute ---
PROJECTS = ['alpha', 'beta', 'gamma']

# --- 2. Simplified, Deterministic Rule-Based Decision Logic ---
def get_decision(user, obj, action):
    # Unpack all attributes, including the internal-only user project
    u_dept, u_desig, u_proj = user['department'], user['designation'], user['project_id']
    o_type, o_sens, o_reg, o_proj = obj['type'], obj['sensitivity'], obj['region'], obj['project_id']

    # --- NEW: High-precedence Constraint Rule on Project ID for 'write' actions ---
    # A user can only write to resources that match their assigned project.
    if action == 'write' and u_proj != o_proj:
        return "Deny"

    # --- High-precedence Data Residency Rule ---
    if o_reg == 'EMEA' and u_dept != 'IT':
        return "Deny"

    # --- Department-Specific Rules ---
    if u_dept == o_type and action in ['read', 'write']:
        if o_sens == 'High' and action == 'write' and u_desig != 'Manager':
            return "Deny"
        return "Allow"

    # --- Cross-Functional Rules ---
    if u_dept == 'IT' and action == 'read':
        return "Allow"
    if u_dept == 'Sales' and u_desig == 'Manager' and o_type == 'Financial' and o_sens == 'Low' and action == 'read':
        return "Allow"
    if o_type == 'General' and action == 'read':
        return "Allow"
        
    return "Deny"

# --- 3. Data Generation Functions ---
def generate_users():
    users = []
    for dept, designations in DEPARTMENTS.items():
        for i in range(len(designations) * 5):
            users.append({
                "user_name": f"{random.choice(FIRST_NAMES).lower()}_{dept.lower()}_{i}", 
                "department": dept, 
                "designation": random.choice(designations),
                "project_id": random.choice(PROJECTS) # Assign project ID internally
            })
    return users

def generate_objects():
    objects = []
    file_ext = {"Financial": "xlsx", "Operational": "csv", "System": "sh", "General": "pdf"}
    for o_type, sensitivities in OBJECTS_STRUCTURE.items():
        for sens in sensitivities:
            for i in range(5):
                objects.append({
                    "object_name": f"{o_type.lower()}_{sens.lower()}_{i}.{file_ext[o_type]}", 
                    "type": o_type, 
                    "sensitivity": sens,
                    "region": random.choice(REGIONS),
                    "project_id": random.choice(PROJECTS) # Assign project ID to object
                })
    return objects

def format_for_file(entity, is_user=True):
    # --- UPDATED: User file still only has 2 attributes, Object file now has 4 ---
    if is_user:
        # NOTE: We are intentionally NOT writing project_id to the user file.
        return f"<{entity['user_name']} department:{entity['department']} designation:{entity['designation']}>"
    else:
        return f"<{entity['object_name']} type:{entity['type']} sensitivity:{entity['sensitivity']} region:{entity['region']} project_id:{entity['project_id']}>"

# --- 4. Main Script Execution ---
def main():
    print("--- Starting SIMPLIFIED Log Generation (2 User Attrs, 4 Resource Attrs) ---")
    all_users, all_objects = generate_users(), generate_objects()
    print(f"Generating {USER_FILE} with {len(all_users)} users and {len(all_objects)} objects.")
    
    with open(USER_FILE, "w") as f: f.write("\n".join([format_for_file(u) for u in all_users]))
    with open(OBJECT_FILE, "w") as f: f.write("\n".join([format_for_file(o, is_user=False) for o in all_objects]))
    
    print(f"Generating logs to reach a target of {TARGET_LOG_ENTRIES} entries...")
    generated_logs, attempts = [], 0
    start_time = datetime.now() - timedelta(hours=12)
    
    while len(generated_logs) < TARGET_LOG_ENTRIES:
        attempts += 1
        user, obj, action = random.choice(all_users), random.choice(all_objects), random.choice(ACTIONS)
        decision = get_decision(user, obj, action)
        
        if decision == "Allow" or (decision == "Deny" and random.random() < (1 - DENY_DROP_PROBABILITY)):
            time_str = (start_time + timedelta(seconds=attempts * random.randint(5, 30))).strftime("%H:%M:%S")
            generated_logs.append(f"<{user['user_name']} {obj['object_name']} {action} {time_str} {decision}>")
    
    print(f"\nWriting {len(generated_logs)} logs to {LOG_FILE} (took {attempts} generation attempts).")
    with open(LOG_FILE, "w") as f: f.write("\n".join(generated_logs))
        
    decision_counts = collections.Counter(log.split()[-1].replace('>', '') for log in generated_logs)
    allow_count = decision_counts.get('Allow', 0)
    deny_count = decision_counts.get('Deny', 0)
    total_count = allow_count + deny_count or 1
    
    print("\n--- Generation Complete! ---")
    print(f"Final Log Ratio: {allow_count} Allow ({allow_count/total_count:.1%}) | {deny_count} Deny ({deny_count/total_count:.1%})")

if __name__ == "__main__":
    main()