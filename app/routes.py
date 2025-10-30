# /app/routes.py
import io
import os
import uuid
import json
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
import pandas as pd
from flask import send_file
from flask import render_template, request, redirect, url_for, session
from app.utils import parse_user_data, parse_object_data, parse_log_data
from app.services import generate_policy, run_programmatic_verification, generate_compression_script, generate_rules_script, generate_natural_language_policy_from_rules
from app.constants import DEFAULT_RULE_PRINCIPLES

main = Blueprint('main', __name__)

# Create temp directory if it doesn't exist
TEMP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'temp')
os.makedirs(TEMP_DIR, exist_ok=True)

def save_script_result(script_data):
    """Save script result to a temporary file and return a unique ID."""
    script_id = str(uuid.uuid4())
    file_path = os.path.join(TEMP_DIR, f"script_{script_id}.json")
    
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(script_data, f, ensure_ascii=False, indent=2)
    
    return script_id

def get_script_result(script_id):
    """Retrieve script result from temporary file."""
    file_path = os.path.join(TEMP_DIR, f"script_{script_id}.json")
    
    if not os.path.exists(file_path):
        return None
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def cleanup_script_result(script_id):
    """Clean up temporary script file."""
    file_path = os.path.join(TEMP_DIR, f"script_{script_id}.json")
    if os.path.exists(file_path):
        os.remove(file_path)

# ---- Temp helpers for Natural Language Policy results ----
def save_policy_result(policy_text, original_rules):
    """Save large natural-language policy output to a temp file and return an ID."""
    policy_id = str(uuid.uuid4())
    file_path = os.path.join(TEMP_DIR, f"nlp_{policy_id}.json")
    data = {
        'policy': policy_text,
        'rules': original_rules,
    }
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return policy_id

def get_policy_result(policy_id):
    """Retrieve stored natural-language policy content by ID."""
    file_path = os.path.join(TEMP_DIR, f"nlp_{policy_id}.json")
    if not os.path.exists(file_path):
        return None
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def cleanup_policy_result(policy_id):
    """Delete stored natural-language policy content by ID."""
    file_path = os.path.join(TEMP_DIR, f"nlp_{policy_id}.json")
    if os.path.exists(file_path):
        os.remove(file_path)

@main.route('/')
def index():
    """Redirect to start page."""
    return redirect(url_for('main.start'))

@main.route('/start')
def start():
    """Initial page with workflow selection."""
    return render_template('start.html')

@main.route('/format-detection/<workflow>', methods=['GET', 'POST'])
def format_detection(workflow):
    """Format detection page for both compression and rules workflows."""
    if request.method == 'POST':
        detection_method = request.form.get('detection_method')
        model_choice = request.form.get('model_choice', 'gemini-2.5-flash')
        
        if detection_method == 'upload':
            # Handle file upload detection
            user_sample_file = request.files.get('user_sample')
            object_sample_file = request.files.get('object_sample')
            log_sample_file = request.files.get('log_sample')
            
            if not (user_sample_file and object_sample_file and log_sample_file):
                flash("Please upload all three sample files.", "error")
                return render_template('format_detection.html', workflow=workflow)
            
            user_sample = user_sample_file.read().decode('utf-8')
            object_sample = object_sample_file.read().decode('utf-8')
            log_sample = log_sample_file.read().decode('utf-8')
            
            # Generate script based on workflow
            if workflow == 'compress':
                result = generate_compression_script(user_sample, object_sample, log_sample, model_choice)
            else:  # rules
                result = generate_rules_script(user_sample, object_sample, log_sample, model_choice)
                
        else:  # describe
            # Handle format description
            user_format = request.form.get('user_format')
            object_format = request.form.get('object_format')
            log_format = request.form.get('log_format')
            
            if not (user_format and object_format and log_format):
                flash("Please provide format descriptions for all three file types.", "error")
                return render_template('format_detection.html', workflow=workflow)
            
            # Generate script based on workflow
            if workflow == 'compress':
                result = generate_compression_script(user_format, object_format, log_format, model_choice)
            else:  # rules
                result = generate_rules_script(user_format, object_format, log_format, model_choice)
        
        # Check for errors
        if 'error' in result:
            flash(result['error'], "error")
            return render_template('format_detection.html', workflow=workflow)
        
        # Debug: Print result to console
        print(f"Script generation result keys: {list(result.keys())}")
        
        # Store result in temporary file and redirect to results
        script_id = save_script_result(result)
        session['script_id'] = script_id
        session['workflow'] = workflow
        print(f"Script saved with ID: {script_id}")
        return redirect(url_for('main.script_results'))
    
    return render_template('format_detection.html', workflow=workflow)

@main.route('/script-results')
def script_results():
    """Display generated script results."""
    script_id = session.get('script_id')
    workflow = session.get('workflow')
    
    print(f"Script results route - script_id: {script_id}")
    print(f"Script results route - workflow: {workflow}")
    
    if not script_id or not workflow:
        flash("No script results found. Please generate a script first.", "error")
        return redirect(url_for('main.start'))
    
    # Retrieve script result from temporary file
    script_result = get_script_result(script_id)
    
    if not script_result:
        flash("Script results not found or expired. Please generate a new script.", "error")
        return redirect(url_for('main.start'))
    
    # Check if script content is empty
    if not script_result.get('script_content'):
        flash("Script generation failed. Please try again.", "error")
        cleanup_script_result(script_id)
        return redirect(url_for('main.start'))
    
    return render_template('script_results.html', 
                         script_content=script_result['script_content'],
                         line_count=script_result['line_count'],
                         dependencies=script_result['dependencies'],
                         timestamp=script_result['timestamp'],
                         script_filename=script_result['script_filename'],
                         workflow=workflow)

@main.route('/cleanup-script/<script_id>')
def cleanup_script(script_id):
    """Clean up temporary script file."""
    cleanup_script_result(script_id)
    return redirect(url_for('main.start'))

@main.route('/policy-generation', methods=['GET', 'POST'])
def policy_generation():
    """Original policy generation workflow."""
    if request.method == 'POST':
        # This route now ONLY handles the form processing
        # Add a default value for safety
        model_choice = request.form.get('model_choice', 'gemini-2.5-flash')

        custom_rules = request.form.get('custom_rules')
        rules_to_use = custom_rules.strip() if custom_rules and custom_rules.strip() else DEFAULT_RULE_PRINCIPLES

        # --- NEW: Decide which rules to use ---
        if custom_rules and custom_rules.strip():
            rules_to_use = custom_rules
        else:
            rules_to_use = DEFAULT_RULE_PRINCIPLES


        user_attributes_file = request.files.get('user_attributes')
        object_attributes_file = request.files.get('object_attributes')
        logs_file = request.files.get('logs')

        if not (user_attributes_file and object_attributes_file and logs_file):
            return render_template('index.html', error="Please upload all three files.", default_rules=DEFAULT_RULE_PRINCIPLES)

        user_data = user_attributes_file.read().decode('utf-8')
        object_data = object_attributes_file.read().decode('utf-8')
        log_data = logs_file.read().decode('utf-8')

        parsed_users = parse_user_data(user_data)
        parsed_objects = parse_object_data(object_data)
        parsed_logs = parse_log_data(log_data)
        print("Length of Parsed Users:", len(parsed_users))  # Debugging line
        print("Lenght of Parsed Objects:", len(parsed_objects))  # Debugging line  
        print("Length of Parsed Logs:", len(parsed_logs))  # Debugging line

        # Convert the lists into DataFrames
        user_df = pd.DataFrame(parsed_users)
        object_df = pd.DataFrame(parsed_objects)
        log_df = pd.DataFrame(parsed_logs)

        enriched_logs = log_df.merge(user_df, on='user_name')
        enriched_logs = enriched_logs.merge(object_df, on='object_name')

        pattern_columns = ['department', 'designation', 'action', 'type', 'sensitivity', 'decision']

        unique_patterns_df = enriched_logs[pattern_columns].drop_duplicates()
        unique_patterns_df = unique_patterns_df.sort_values(by=['department', 'designation', 'decision']).reset_index(drop=True)
        print(f"Log entries reduced from {len(log_df)} to {len(unique_patterns_df)} unique patterns.")

        allow_unique_patterns = unique_patterns_df[unique_patterns_df['decision'] == 'Allow']
        deny_unique_patterns = unique_patterns_df[unique_patterns_df['decision'] == 'Deny']
        print(f"Unique Allow patterns: {len(allow_unique_patterns)}")
        print(f"Unique Deny patterns: {len(deny_unique_patterns)}")

        allow_log_data_string = allow_unique_patterns.to_string(index=False, header=False)
        deny_log_data_string = deny_unique_patterns.to_string(index=False, header=False)
        # Step 1: Generate the policy and rules
        rules, policy = generate_policy( allow_log_data_string,deny_log_data_string, rules_to_use, model_choice)
        print(rules)  # For debugging
        if not policy or not rules:
            # If generation fails, show the error message from the policy variable
            return render_template('index.html', error=policy, default_rules=DEFAULT_RULE_PRINCIPLES)

        print(policy)

        # Step 2: Get the verification results using the generated rules
        print(unique_patterns_df)
        verification_report = run_programmatic_verification(rules, unique_patterns_df)
        print(verification_report)  # For debugging
        # CORRECT LOGIC: Store results in the session
        session['policy'] = policy
        session['verification_report'] = verification_report

        # CORRECT LOGIC: Redirect the user to the results page
        return redirect(url_for('main.results'))

    # For a GET request, just show the main upload page
    return render_template('index.html', error=None, default_rules=DEFAULT_RULE_PRINCIPLES)


@main.route('/results')
def results():
    # This NEW route displays results stored in the session
    policy = session.get('policy')
    verification_report = session.get('verification_report')

    # if not policy or not verification_report:
        # return redirect(url_for('main.index'))

    return render_template('results.html', policy=policy, verification_report=verification_report)


@main.route('/natural-language-policy', methods=['GET', 'POST'])
def natural_language_policy():
    """Route for converting rules to natural language policy."""
    if request.method == 'POST':
        rules_text = request.form.get('rules_text')
        model_choice = request.form.get('model_choice', 'gemini-2.5-flash')
        
        if not rules_text or not rules_text.strip():
            flash("Please provide the rules text.", "error")
            return render_template('natural_language_policy.html')
        
        # Generate natural language policy
        natural_language_policy = generate_natural_language_policy_from_rules(rules_text, model_choice)
        
        # Store only a small ID in session (large content saved to temp file)
        policy_id = save_policy_result(natural_language_policy, rules_text)
        session['nlp_id'] = policy_id
        
        return redirect(url_for('main.natural_language_results'))
    
    return render_template('natural_language_policy.html')

@main.route('/natural-language-results')
def natural_language_results():
    """Display the generated natural language policy."""
    policy_id = session.get('nlp_id')
    if not policy_id:
        flash("No policy found. Please generate a policy first.", "error")
        return redirect(url_for('main.natural_language_policy'))

    stored = get_policy_result(policy_id)
    if not stored:
        flash("Policy result expired or missing. Please generate again.", "error")
        return redirect(url_for('main.natural_language_policy'))

    return render_template('natural_language_results.html', 
                         policy=stored.get('policy', ''), 
                         original_rules=stored.get('rules', ''))

@main.route('/download', methods=['POST'])
def download():
    """
    Handles the file download when the user clicks the download button.
    """
    policy_text = request.form.get('policy_text')
    if policy_text:
        memory_file = io.BytesIO()
        memory_file.write(policy_text.encode('utf-8'))
        memory_file.seek(0)
        
        return send_file(
            memory_file,
            download_name='generated_policy.txt',
            as_attachment=True,
            mimetype='text/plain'
        )
    # Redirect back to home if something goes wrong
    return redirect(url_for('main.index'))