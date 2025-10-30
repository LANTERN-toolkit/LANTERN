# /app/services.py
import google.generativeai as genai
import pandas as pd
import json
import re
import os
from datetime import datetime
from flask import current_app

from app.PolicyTree import PolicyTree

# Configure Google API key
def configure_google_api():
    """Configure Google Generative AI API key."""
    api_key = current_app.config.get('GOOGLE_API_KEY')
    if api_key:
        genai.configure(api_key=api_key)
    else:
        raise ValueError("GOOGLE_API_KEY not found in configuration")

# (Copy the JSON rule parser from our previous discussion here)
def parse_llm_rules_from_json(rules_text: str) -> list[dict]:
    """
    Extracts the JSON block from the LLM's response and parses it into a list of rule dictionaries.
    """
    try:
        # Clean up the rules text first
        cleaned_text = rules_text.strip()
        
        # Try to find JSON block
        json_start = cleaned_text.find('```json')
        json_end = cleaned_text.rfind('```')
        
        if json_start != -1 and json_end != -1 and json_end > json_start:
            json_str = cleaned_text[json_start + 7:json_end].strip()
        else:
            # Try to find just the JSON array
            json_start = cleaned_text.find('[')
            json_end = cleaned_text.rfind(']')
            if json_start != -1 and json_end != -1 and json_end > json_start:
                json_str = cleaned_text[json_start:json_end + 1]
            else:
                json_str = cleaned_text
        
        print(f"Attempting to parse JSON: {json_str[:200]}...")
        
        parsed_rules = json.loads(json_str)
        
        if not isinstance(parsed_rules, list):
            print(f"Error: Expected list, got {type(parsed_rules)}")
            return []
        
        flattened_rules = []
        for i, rule in enumerate(parsed_rules):
            try:
                if not isinstance(rule, dict):
                    print(f"Error: Rule {i} is not a dictionary: {rule}")
                    continue
                
                flat_rule = {
                    'decision': rule.get('decision', 'Permit'),
                    'action': rule.get('action', '*'),
                    'original_text': json.dumps(rule)
                }

                # Extract conditions and target attributes
                conditions = rule.get('conditions', {})
                target = rule.get('target', {})
                
                # Add all conditions and target attributes to the flat rule
                flat_rule.update(conditions)
                flat_rule.update(target)
                
                # Ensure we have the required attributes with defaults
                for attr in ['department', 'designation', 'type', 'sensitivity']:
                    if attr not in flat_rule:
                        flat_rule[attr] = '*'
                
                flattened_rules.append(flat_rule)
                print(f"Successfully parsed rule {i}: {flat_rule}")
                
            except Exception as e:
                print(f"Error parsing rule {i}: {e}")
                print(f"Rule content: {rule}")
                continue
        
        print(f"Successfully parsed {len(flattened_rules)} rules")
        return flattened_rules
    
    except (json.JSONDecodeError, KeyError, Exception) as e:
        print(f"Error parsing JSON from LLM response: {e}")
        print(f"Raw response part received: {rules_text[:500]}...")
        return []  # Return an empty list on failure


def generate_policy(allow_patterns_string: str, deny_patterns_string:str,rule_principles: str, model_name: str):
    """Formats the prompt and calls the Generative AI model to generate rules and a policy."""
    try:
        configure_google_api()
    except ValueError as e:
        return None, f"Configuration error: {e}"
    
    # BUG FIX: Added the missing Stage 2 instructions to the prompt.
    prompt_template = f'''
    You are a meticulous cybersecurity analyst applying the Principle of Least Privilege. Your task is to derive precise, attribute-based access control rules.

    ### Your Goal
    Create a comprehensive set of `Permit` rules that cover ALL the "Allowed Access Patterns" while simultaneously NOT permitting any of the "Denied Access Patterns." Your rules must be specific enough to avoid false positives but comprehensive enough to achieve 100% coverage of allowed patterns.

    **Rule Extraction Principles:**
    {rule_principles}

    ---
    ### Input Data

    #### 1. Allowed Access Patterns (Your rules MUST cover these - 100% coverage required)
    {allow_patterns_string}

    #### 2. Denied Access Patterns (Your rules MUST NOT match any of these)
    {deny_patterns_string}
    ---
    ### Your Output Format

    Provide your analysis in exactly the structure below. For Stage 1, you MUST provide the output as a JSON array of rule objects, enclosed in a markdown JSON block.

    **STAGE 1: EXTRACTED RULES**
    **CRITICAL REQUIREMENTS:**
    - Generate rules that achieve 100% coverage of ALL allowed patterns
    - Use wildcards (*) strategically to generalize patterns while avoiding denied patterns
    - Create multiple overlapping rules if necessary to ensure complete coverage
    - Each rule must have ALL required fields: decision, conditions, action, target
    - All values for keys inside the 'conditions' and 'target' objects MUST be simple strings (not arrays)

    ```json
    [
      {{
        "decision": "Permit",
        "conditions": {{"department": "Finance", "designation": "Analyst"}},
        "action": "read",
        "target": {{"type": "Financial", "sensitivity": "Low"}}
      }},
      {{
        "decision": "Permit", 
        "conditions": {{"department": "*", "designation": "Manager"}},
        "action": "*",
        "target": {{"type": "*", "sensitivity": "Low"}}
      }}
    ]
    ```

    **COVERAGE STRATEGY:**
    1. Start with specific rules for exact patterns
    2. Add generalized rules using wildcards (*) for broader coverage
    3. Ensure every single allowed pattern is covered by at least one rule
    4. Verify no denied patterns are accidentally permitted
    5. Use overlapping rules if necessary to achieve 100% coverage

    ---POLICY-BOUNDARY---
    **STAGE 2: NATURAL LANGUAGE POLICY**
    Task: Transform the technical rules into a professional, narrative-style policy summary suitable for a management audience. The goal is to tell the story of our access control strategy.
    Tone and Style:
    Professional and Authoritative: Write as a senior analyst explaining the policy.
    Paragraph Form: Use full, flowing paragraphs. Do NOT use bullet points.
    Thematic Grouping: Instead of listing by department, group related concepts. Start with broad, low-risk access and move to the most privileged and sensitive access.
    Example of Desired Output Structure:
    Opening Statement: Begin with a brief, high-level summary of the policy's purpose.
    General Access & Transparency: Describe permissions that are widely available, such as access to common HR documents. This shows a baseline of trust and transparency.
    Standard Departmental Operations: Explain how roles within key departments (e.g., Sales, Marketing, Finance) are empowered to perform their daily duties with access to necessary operational data.
    Managing Sensitive Information: Detail how access to sensitive data (e.g., Medium or High sensitivity in Finance, HR, Legal) is carefully restricted to senior roles or managers. This highlights the principle of least privilege.
    Controlling Critical Infrastructure: Specifically address the high-impact permissions granted to the IT department, framing them in the context of system maintenance and security.
    Concluding Remark: End with a brief sentence that reinforces the policy's goal of balancing security and operational agility.
    Example of Desired Output (Based on the rules you provided):
    "This Access Control Policy is strategically designed to align with the Principle of Least Privilege, ensuring that employees have precisely the access required to fulfill their roles while robustly protecting the company's sensitive assets.
    A foundational element of our policy is providing broad access to common administrative information. Employees across nearly all departments, including Sales, Engineering, and Operations, are granted read-access to Low-sensitivity HR documents, ensuring transparency for essential company-wide information.
    For daily operations, departmental staff are appropriately empowered. For example, Marketing Analysts can manage campaign materials with write-access to Low-sensitivity marketing files, while Sales Representatives are equipped with read-access to the Operational data necessary for their roles. In Finance, Analysts can manage routine financial records, and Senior Analysts can review more sensitive Medium-sensitivity data, facilitating standard departmental workflows........
    '''
    try:
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(prompt_template)
        
        raw_text = response.text
        seperator = "---POLICY-BOUNDARY---"

        if seperator not in raw_text:
            return None, "Error: The response from the Generative AI model is missing the expected policy boundary separator."
        
        rules_text, policy_summary = map(str.strip, raw_text.split(seperator, 1))
        # Clean up the rules_text to remove any leading text before the JSON block


        rules_cleaned = rules_text.replace("STAGE 1: EXTRACTED RULES", "").strip()
        policy_cleaned = policy_summary.replace("STAGE 2: NATURAL LANGUAGE POLICY", "").strip()

        return rules_cleaned, policy_cleaned  # Return rules text and no error
            
    except Exception as e:
        return None, f"An error occurred while calling the Generative AI model: {e}"
    

def get_verification_results(logs, rules,model_name="gemini-2.5-flash"):
    """
    Makes the SECOND API call to get the verification results (TP, TN, etc.).
    """
    try:
        configure_google_api()
    except ValueError as e:
        return f"Configuration error: {e}"
    verification_prompt_template = f'''
    You are a meticulous and logical security policy auditor. Your primary task is to verify a given set of access control rules against a log of access events. Accuracy is critical.
    **IMPORTANT FIRST STEP:** Before doing anything else, count the exact number of lines in the "Access Control Log" provided below and state this number. This is your ground truth for the total entries.
### Input Data

The log entries look like this:
<department designation action type sensitivity decision>

#### 1. Access Control Log (The Ground Truth)
{logs}

#### 2. The Policy to be Verified (The Candidate Rules)
{rules}

### Your Verification Process (Follow these steps precisely and without deviation)

1.  **Initial Count:** First, count the total number of entries in the "Access Control Log." Count the number of "Allow" entries and the number of "Deny" entries separately. Write these numbers down for your final check.

2.  **Line-by-Line Analysis:** Iterate through **every single line** of the Access Control Log, from the first to the last. For each log entry, perform the following:
    a. **Enrich the Log Entry:** Using the User and Object data, determine the full set of attributes for the user and object in the current log entry.
    b. **Decision Check:** Look at the log's `Decision` (`Allow` or `Deny`).
    c. **Policy Matching:** Systematically compare the enriched log entry against **every rule** in the "Policy to be Verified" list. A log entry "matches" a rule if all of its attributes (subject, object, action) are consistent with that rule.
    d. **Categorize the Outcome:** Based on the `Decision` and whether a match was found, categorize the log entry into one of four categories:
        *   **True Positive (TP):** Log is `Allow`, and you found at least one matching `Permit` rule.
        *   **False Negative (FN):** Log is `Allow`, but you found **no** matching `Permit` rule. (The policy is missing a rule).
        *   **True Negative (TN):** Log is `Deny`, and you correctly found **no** matching `Permit` rule. (A `DENY` rule is not required for a TN).
        *   **False Positive (FP):** Log is `Deny`, but you found a `Permit` rule that wrongly matched it. (The policy is too permissive).

3.  **Final Tally and Calculation:**
    a. Sum the total counts for TP, FN, TN, and FP from your line-by-line analysis.
    b. **Sanity Check (Crucial):** Verify that `(TP + FN)` equals your initial "Allow" count, and `(TN + FP)` equals your initial "Deny" count. **Your final reported numbers must be consistent with the total log size.**
    c. **Calculate Final Metrics:**
        *   Log Coverage = `TP / (TP + FN)` * 100
        *   Rule Accuracy = `TN / (TN + FP)` * 100

### Your Final Output

Provide the final analysis in the following strict, clean format. Do not add any extra explanations.

Total Log Entries Analyzed: [Your initial count from Step 1]
- Allowed Events: [Your initial 'Allow' count from Step 1]
- Denied Events: [Your initial 'Deny' count from Step 1]

Verification Results:
- True Positives (TP): [Your final tally from Step 3]
- False Negatives (FN): [Your final tally from Step 3]
- True Negatives (TN): [Your final tally from Step 3]
- False Positives (FP): [Your final tally from Step 3]

Metrics:
- Log Coverage: [Calculated Percentage]%
- Rule Accuracy: [Calculated Percentage]%
    '''
    try:
        # Dynamically create the model based on user's choice
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(verification_prompt_template)
        return response.text.strip()
    except Exception as e:
        return f"An error occurred during verification: {e}"



def run_programmatic_verification(rules_text: str, enriched_logs_df: pd.DataFrame) -> str:
    """
    Builds a PolicyTree from LLM rules, verifies ALL logs against it, and returns a formatted report.
    This function performs the entire Parse -> Build -> Verify process.
    """

    ### Attributes for the PolicyTree (must match those used in rules and logs)
    attributes = ['department', 'designation', 'action', 'type', 'sensitivity']
    
    # --- STAGE 1: PARSE ---
    print(f"Starting verification with {len(enriched_logs_df)} log entries")
    parsed_rules = parse_llm_rules_from_json(rules_text)
    
    if not parsed_rules:
        return "Error: No rules were successfully parsed from the LLM response."
    
    print(f"Successfully parsed {len(parsed_rules)} rules")
    for i, rule in enumerate(parsed_rules):
        print(f"Rule {i+1}: {rule}")
    
    # --- STAGE 2: BUILD ---
    
    policy_tree = PolicyTree(attributes_order=attributes)
    for rule in parsed_rules:
        policy_tree.add_rule(rule)
        
    # --- STAGE 3: VERIFY & REPORT ---
    tp, fn, tn, fp = 0, 0, 0, 0
    allow_count = len(enriched_logs_df[enriched_logs_df['decision'] == 'Allow'])
    deny_count = len(enriched_logs_df[enriched_logs_df['decision'] == 'Deny'])

    print(f"Verifying {allow_count} Allow entries and {deny_count} Deny entries")

    for idx, log_row in enriched_logs_df.iterrows():
        log_dict = log_row.to_dict()
        actual_decision = log_dict.get('decision')
        
        predicted_decision, matched_rule = policy_tree.verify_log(log_dict)
        
        # Debug output for first few entries
        if idx < 5:
            print(f"Log {idx}: {log_dict} -> Predicted: {predicted_decision}, Actual: {actual_decision}")
            if matched_rule:
                print(f"  Matched rule: {matched_rule}")

        if actual_decision == 'Allow' and predicted_decision == 'Permit':
            tp += 1
        elif actual_decision == 'Allow' and predicted_decision != 'Permit':
            fn += 1
        elif actual_decision == 'Deny' and predicted_decision != 'Permit':
            tn += 1
        elif actual_decision == 'Deny' and predicted_decision == 'Permit':
            fp += 1
            
    # Calculate final metrics
    log_coverage = (tp / allow_count * 100) if allow_count > 0 else 0
    rule_accuracy = (tn / deny_count * 100) if deny_count > 0 else 0
    
    print(f"Verification complete: TP={tp}, FN={fn}, TN={tn}, FP={fp}")
    print(f"Coverage: {log_coverage:.2f}%, Accuracy: {rule_accuracy:.2f}%")
    
    # Format the final report string
    report = f"""
Total Log Entries Analyzed: {len(enriched_logs_df)}
- Allowed Events: {allow_count}
- Denied Events: {deny_count}

Verification Results:
- True Positives (TP): {tp}
- False Negatives (FN): {fn}
- True Negatives (TN): {tn}
- False Positives (FP): {fp}

Metrics:
- Log Coverage: {log_coverage:.2f}%
- Rule Accuracy: {rule_accuracy:.2f}%
"""
    return report.strip()


def generate_compression_script(user_sample: str, object_sample: str, log_sample: str, model_name: str = "gemini-2.5-flash") -> dict:
    """Generate a log compression script based on sample data files."""
    try:
        configure_google_api()
    except ValueError as e:
        return {
            'error': f"Configuration error: {e}",
            'script_content': '',
            'line_count': 0,
            'dependencies': '',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'script_filename': 'log_compressor.py'
        }
    
    # Enhanced prompt with the provided template
    compression_prompt = f'''
# Log Compression Script Generation Task

## Objective
Generate a Python script that can dynamically parse access control logs in various formats and compress them by extracting unique access patterns for ABAC policy mining.

## Input Files Structure
The script should read from three text files:
1. `users.txt` - Contains user data with attributes
2. `objects.txt` - Contains object/resource data with attributes
3. `logs.txt` - Contains access control log entries

## Sample Input Formats

### users.txt (sample):
{user_sample}

### objects.txt (sample):
{object_sample}

### logs.txt (sample):
{log_sample}

## Requirements for Generated Script
1. Dynamic Format Detection
- Analyze the structure of each input file
- Automatically detect delimiters, field positions, and data patterns
- Handle variations in format (different separators, field orders, etc.)

2. Core Functionality
- Generate functions to:
  - Parse user data and extract attributes (name, department, designation, etc.)
  - Parse object data and extract attributes (name, type, sensitivity, etc.)
  - Parse log entries and extract (user, object, action, decision) while removing timestamps
  - Merge all data sources to create enriched log entries
  - Extract unique access patterns for compression

3. Compression Logic
- Combine user attributes, object attributes, and access decisions
- Remove duplicate patterns to compress the dataset
- Sort patterns logically (by department, designation, decision)
- Output compressed patterns in a structured format

4. Error Handling
- Handle malformed lines gracefully
- Provide informative error messages
- Skip invalid entries and continue processing
- Report statistics (total lines processed, errors encountered, compression ratio)

5. Output Format
- Generate a final compressed dataset containing columns like:
  ['department', 'designation', 'action', 'type', 'sensitivity', 'decision']

## Script Structure Template
The generated script should include:
- File Reading Functions: Read and validate input files
- Format Analysis Functions: Detect patterns in data structure
- Dynamic Parser Generation: Create appropriate parsing logic based on detected format
- Data Processing Pipeline: Parse, merge, and compress data
- Output Generation: Save compressed patterns to file or return structured data
- Main Execution: Orchestrate the entire process

## Expected Output
Generate a complete, executable Python script that:
- Takes file paths as input parameters
- Automatically adapts to different log formats
- Produces compressed access patterns suitable for ABAC rule generation
- Includes proper error handling and logging
- Provides compression statistics and processing summary

## Additional Constraints
- Use only standard Python libraries (pandas, re, os, sys)
- Make the script modular and reusable
- Include detailed comments explaining the logic
- Ensure the script can handle large log files efficiently
- Provide clear variable names and function documentation

Please generate the complete Python script that fulfills these requirements.

# Sample Reference Code for Dynamic Log Compression
# Include this in your LLM prompt as a reference template

import pandas as pd
import re
from typing import List, Dict

class LogCompressor:
    def __init__(self):
        self.stats = {{'processed': 0, 'errors': 0, 'compression_ratio': 0.0}}

    def analyze_format(self, sample_lines: List[str]) -> Dict:
        """Analyze input format to detect patterns"""
        format_info = {{
            'has_brackets': any(line.strip().startswith('<') for line in sample_lines[:3]),
            'field_count': 0,
            'delimiter': ' '
        }}

        # Detect field count and delimiter
        for line in sample_lines[:5]:
            clean_line = line.strip()[1:-1] if format_info['has_brackets'] else line.strip()
            parts = clean_line.split()
            format_info['field_count'] = max(format_info['field_count'], len(parts))

        return format_info

    def detect_pattern(self, lines: List[str], data_type: str) -> str:
        """Dynamically detect regex pattern based on data type"""
        format_info = self.analyze_format(lines)

        # Default patterns to try
        if data_type == 'user':
            patterns = [
                r'<(\w+)\s+department:(\S+)\s+designation:(.*)>',
                r'(\w+)\s+(\w+)\s+(.*)',
                r'(\w+),(\w+),(.*)'
            ]
        elif data_type == 'object':
            patterns = [
                r'<(\S+)\s+type:(\S+)\s+sensitivity:(\S+)>',
                r'(\S+)\s+(\S+)\s+(\S+)',
                r'(\S+),(\S+),(\S+)'
            ]
        elif data_type == 'log':
            patterns = [
                r'<(\S+)\s+(\S+)\s+(\S+)\s+([^\s]+)\s+(\S+)>',
                r'(\S+)\s+(\S+)\s+(\S+)\s+(\S+)',
                r'(\S+),(\S+),(\S+),([^,]+),(\S+)'
            ]

        # Test patterns and return the first matching one
        for pattern in patterns:
            if self.test_pattern(pattern, lines[:5]):
                return pattern

        # Generate dynamic pattern if none match
        return self.create_dynamic_pattern(lines[0] if lines else "", format_info)

    def test_pattern(self, pattern: str, sample_lines: List[str]) -> bool:
        """Test if pattern matches sample data"""
        regex = re.compile(pattern)
        matches = sum(1 for line in sample_lines if line.strip() and regex.search(line))
        return matches >= len([l for l in sample_lines if l.strip()]) * 0.8

    def create_dynamic_pattern(self, sample_line: str, format_info: Dict) -> str:
        """Create pattern based on detected format"""
        field_count = format_info['field_count']
        has_brackets = format_info['has_brackets']

        base_pattern = r'(\S+)\s+' * (field_count - 1) + r'(.*)'
        return f'<{{base_pattern}}>' if has_brackets else base_pattern

    def parse_data(self, file_path: str, data_type: str) -> List[Dict]:
        """Generic parsing function"""
        try:
            with open(file_path, 'r') as file:
                lines = [line for line in file.readlines() if line.strip()]

            pattern = self.detect_pattern(lines, data_type)
            regex = re.compile(pattern)

            parsed_data = []
            for line_num, line in enumerate(lines, 1):
                try:
                    match = regex.search(line.strip())
                    if match:
                        groups = match.groups()

                        # Map fields based on data type
                        if data_type == 'user':
                            data = {{
                                'user_name': groups[0],
                                'department': groups[1] if len(groups) > 1 else 'unknown',
                                'designation': groups[2] if len(groups) > 2 else 'unknown'
                            }}
                        elif data_type == 'object':
                            data = {{
                                'object_name': groups[0],
                                'type': groups[1] if len(groups) > 1 else 'unknown',
                                'sensitivity': groups[2] if len(groups) > 2 else 'unknown'
                            }}
                        elif data_type == 'log':
                            data = {{
                                'user_name': groups[0],
                                'object_name': groups[1],
                                'action': groups[2],
                                'decision': groups[4] if len(groups) == 5 else groups[3]  # Skip timestamp
                            }}

                        parsed_data.append(data)
                        self.stats['processed'] += 1
                    else:
                        print(f"Warning: Could not parse line {{line_num}}")
                        self.stats['errors'] += 1

                except Exception as e:
                    print(f"Error parsing line {{line_num}}: {{e}}")
                    self.stats['errors'] += 1

            return parsed_data

        except Exception as e:
            print(f"Error reading file {{file_path}}: {{e}}")
            return []

    def compress_logs(self, user_file: str, object_file: str, log_file: str) -> pd.DataFrame:
        """Main compression pipeline"""
        # Parse data
        users = self.parse_data(user_file, 'user')
        objects = self.parse_data(object_file, 'object')
        logs = self.parse_data(log_file, 'log')

        # Convert to DataFrames
        user_df = pd.DataFrame(users)
        object_df = pd.DataFrame(objects)
        log_df = pd.DataFrame(logs)

        # Merge and compress
        enriched_logs = log_df.merge(user_df, on='user_name').merge(object_df, on='object_name')

        pattern_columns = ['department', 'designation', 'action', 'type', 'sensitivity', 'decision']
        unique_patterns = enriched_logs[pattern_columns].drop_duplicates()

        # Calculate compression ratio
        original_size = len(enriched_logs)
        compressed_size = len(unique_patterns)
        self.stats['compression_ratio'] = (1 - compressed_size/original_size) * 100

        return unique_patterns.sort_values(['department', 'designation', 'decision']).reset_index(drop=True)

# Example usage:
# compressor = LogCompressor()
# result = compressor.compress_logs('users.txt', 'objects.txt', 'logs.txt')
# print(f"Compressed from {{compressor.stats['processed']}} to {{len(result)}} patterns")
# print(f"Compression ratio: {{compressor.stats['compression_ratio']:.2f}}%")
'''
    
    try:
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(compression_prompt)
        
        script_content = response.text.strip()
        
        # Extract script if it's wrapped in code blocks
        if '```python' in script_content:
            start = script_content.find('```python') + 9
            end = script_content.rfind('```')
            if end > start:
                script_content = script_content[start:end].strip()
        elif '```' in script_content:
            start = script_content.find('```') + 3
            end = script_content.rfind('```')
            if end > start:
                script_content = script_content[start:end].strip()
        
        # Count lines and dependencies
        lines = script_content.split('\n')
        line_count = len([line for line in lines if line.strip()])
        
        # Extract dependencies from imports
        dependencies = []
        for line in lines:
            if line.strip().startswith('import ') or line.strip().startswith('from '):
                if 'pandas' in line:
                    dependencies.append('pandas')
                elif 'numpy' in line:
                    dependencies.append('numpy')
                elif 're' in line:
                    dependencies.append('re')
        
        dependencies = list(set(dependencies)) if dependencies else ['pandas', 're']
        
        return {
            'script_content': script_content,
            'line_count': line_count,
            'dependencies': ', '.join(dependencies),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'script_filename': 'log_compressor.py'
        }
        
    except Exception as e:
        return {
            'error': f"An error occurred while generating the compression script: {e}",
            'script_content': '',
            'line_count': 0,
            'dependencies': '',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'script_filename': 'log_compressor.py'
        }


def generate_natural_language_policy_from_rules(rules_text: str, model_name: str = "gemini-2.5-flash") -> str:
    """
    Converts rules from dictionary format to natural language policy using LLM.
    
    Args:
        rules_text: String containing rules in the format:
                   Rule 1: ⟨User_Expr: {'designation': {'Manager', 'Coordinator'}}, 
                   Resource_Expr: {'sensitivity': {'Medium'}}, Operations: {'write', 'read'}, 
                   Constraints: {'department = type'}⟩
                   WSC (Complexity): 6
                   Approx. True Positive Coverage: 2.89% of total allowed permissions.
        model_name: Name of the LLM model to use
        
    Returns:
        Natural language policy description
    """
    try:
        configure_google_api()
    except ValueError as e:
        return f"Configuration error: {e}"
    
    # Enhanced prompt for converting rules to natural language
    natural_language_policy_prompt = f'''
    You are a Cybersecurity Analyst tasked with communicating complex security policies to business leaders. Your writing style is clear, concise, and authoritative, translating technical details into business-centric principles.

### Your Task
Transform the technical ABAC rules below into a professional executive summary. The summary is for a non-technical business leader (e.g., a department head or CEO) who needs to understand our data protection strategy without getting lost in technical jargon.

### Input Rules
{rules_text}

### Writing Guidelines

**Tone and Style:**
- **Professional & Authoritative:** Write with confidence. The goal is to reassure leadership that a sensible, robust system is in place.
- **Clear & Concise:** Use direct language. Avoid slang, overly casual phrases ("Hey!"), and unnecessary storytelling fluff.
- **Business-Focused:** Frame the explanation around concepts like risk management, operational efficiency, and data protection.

**Content Focus:**
- Explain the **"why"** (the business logic and security principles) behind the rules, not just the "what."
- Connect access controls directly to job functions and responsibilities that a leader would understand.
- Emphasize how the policies **enable** the business to operate securely, rather than just restricting people.

### Report Structure:
1.  **Opening Statement:** Begin with a concise summary of the policy's purpose and the principles it's built on.
2.  **Core Access Principles:** Explain the fundamental logic of the access model. Structure this section with clear headings like:
    *   **Role-Based Access:** Explain that access is determined by an employee's role and department.
    *   **Data Sensitivity:** Explain how more sensitive data has stricter controls.
    *   **Principle of Least Privilege:** Briefly touch on the idea that employees are only given the access they absolutely need to perform their jobs.
3.  **Cross-Functional Collaboration:** Describe how the policies securely allow teams (like IT, Legal, and Finance) to work together and access data across departments when necessary.
4.  **Business Impact & Conclusion:** End with a strong statement about how these controls protect the company's assets, manage risk, and support operational goals.

**Language Tips:**
- Instead of "rules," use "policies" or "controls."
- Instead of "safe," use "secure," "protected," and "compliant."
- Instead of "job role," you can also use "job function" or "responsibilities."
- Instead of "special keys," use "elevated privileges" or "specific permissions."
- Use headings and bullet points to make the summary scannable and easy to digest.

**Example Style (for the new, professional tone):**
"This document provides an overview of our Information Access Control Policy. Our approach is built on the core security principles of 'Least Privilege' and 'Role-Based Access' to ensure our data remains secure while maintaining operational efficiency.

**Key Principles of Our Policy:**

*   **Access is Tied to Job Function:** An employee's access rights are directly determined by their role and department. For example, the Finance team has access to financial systems, while the Engineering team has access to source code repositories. This ensures that staff can only view and modify data relevant to their specific responsibilities.
*   **Controls are Based on Data Sensitivity:** Stricter controls are applied to our most sensitive information. Access to confidential HR records or strategic financial data is limited to a small number of senior personnel with a clear business need.

These controls are designed to effectively manage risk and protect our critical information assets, ensuring a secure foundation for all our business operations."

### Important Notes:
- Focus on the main patterns that demonstrate intelligent design.
- The summary should build confidence and demonstrate competence.
- Make it sound like an official, but easy-to-understand, internal memo.

Write a professional executive summary that explains these access control rules.
    '''
    
    try:
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(natural_language_policy_prompt)
        return response.text.strip()
    except Exception as e:
        return f"An error occurred while generating the natural language policy: {e}"


def generate_rules_script(user_format: str, object_format: str, log_format: str, model_name: str = "gemini-2.5-flash") -> dict:
    """Generate an ABAC rules generation script based on format descriptions."""
    try:
        configure_google_api()
    except ValueError as e:
        return {
            'error': f"Configuration error: {e}",
            'script_content': '',
            'line_count': 0,
            'dependencies': '',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'script_filename': 'abac_rules_generator.py'
        }
    
    # Enhanced prompt with the provided template
    rules_prompt = f'''
    You are an expert Python developer specializing in writing robust, clean, and self-contained data processing scripts. Your task is to create a complete, runnable Python script for a cybersecurity project.

### Project Context
We are building a system to mine Attribute-Based Access Control (ABAC) policies from various data sources. The core of our system is a Python class called `ABACPolicyMiner` which ingests data in specific, structured Python formats.

Our raw data comes from three separate text files (`users.txt`, `resources.txt`, `logs.txt`) with a custom format. We need a complete script that reads these files, parses them correctly, and runs the policy mining algorithm.

### Your Task
Your goal is to write a complete Python script. This script must contain two main parts:
1.  A universal parsing function called `parse_data_file`.
2.  A `main` function that orchestrates the entire process of reading, parsing, and mining.

### Part 1: Detailed Requirements for the `parse_data_file` function

Your primary task is to implement a robust parsing function with the following signature:
`def parse_data_file(file_content: str, file_type: str) -> Union[Dict, List]:`
The function must correctly parse raw text content from `users.txt`, `resources.txt`, and `logs.txt` into the required Python data structures. Instead of following a fixed format, you must **analyze the provided data examples below to infer the correct parsing logic for each file type.**
**General Parsing Rules (CRITICAL):**
1.  **Analyze Line Structure:** Carefully examine the examples for each file type to determine how each line is structured. Pay attention to delimiters (spaces, commas, etc.), wrapping characters (like `<` and `>`), and quoting characters (like `"`) it can have any wrapping character not only (<>,""). Your code must handle the specific patterns you observe.
2.  **Ignore Noise:** The function must be robust. It must always ignore lines that start with a `#` (comments) and any blank lines.
3.  **Error Handling:** If a line does not match the primary pattern you've inferred, your function should print a clear warning message to the console and skip that line, continuing to the next one. Do not let one malformed line crash the entire script.
**Data Structure Requirements:**
*   For `file_type` 'user' or 'resource', the function must return a single dictionary where keys are the primary entity names and values are dictionaries of their attributes.
*   For `file_type` 'log', the function must return a list of dictionaries, where each dictionary represents a single log entry.

### Part 2: Detailed Requirements for the `main` function

1.  **File Handling:** The `main` function must handle reading the three required data files. The filenames are fixed and must be:
    *   `users_filename = "users.txt"`
    *   `resources_filename = "resources.txt"`
    *   `logs_filename = "logs.txt"`
2.  **Orchestration:** The function must perform the following steps in order:
    a.  Read the content of `users.txt`, `resources.txt`, and `logs.txt`. Use a `try...except FileNotFoundError` block for each read operation to handle missing files gracefully.
    b.  Call your `parse_data_file` function for each file's content to get the structured Python data.
    c.  Instantiate the `ABACPolicyMiner` class.
    d.  Call the `miner.load_data()` method with the parsed user, resource, and log data.
    e.  Call the `miner.mine_abac_policy()` method to get the final rules.
    f.  Print the generated rules to the console in a clear, readable format.

### File Format Information
Based on the provided format descriptions, your script should handle these specific formats:

**User Data Format:**
    {user_format}

**Object/Resource Data Format:**
    {object_format}

**Log Data Format:**
    {log_format}

### CRITICAL CONTEXT: The `ABACPolicyMiner` and `ABACRule` Classes

The following Python code for `ABACRule` and `ABACPolicyMiner` is provided. Your generated script MUST be fully compatible with these classes.

```python
from typing import Dict, Set, List, Tuple, Optional, Union
from collections import defaultdict
import copy
import math
import os 

class ABACRule:
    """Enhanced ABAC Rule with improved quality metrics."""
    def __init__(self, user_expr: Dict[str, Set[str]], resource_expr: Dict[str, Set[str]],
                 operations: Set[str], constraints: Set[str]):
        self.user_expr = user_expr
        self.resource_expr = resource_expr
        self.operations = operations
        self.constraints = constraints

    def wsc(self) -> int:
        """Weighted Structural Complexity."""
        complexity = 0
        for attr_vals in self.user_expr.values():
            complexity += len(attr_vals)
        for attr_vals in self.resource_expr.values():
            complexity += len(attr_vals)
        complexity += len(self.operations) + len(self.constraints)
        return complexity

    def __str__(self):
        return f"⟨User_Expr: {{self.user_expr}}, Resource_Expr: {{self.resource_expr}}, Operations: {{self.operations}}, Constraints: {{self.constraints}}⟩"

class ABACPolicyMiner:
    """Enhanced ABAC Policy Miner with research-based improvements."""
    
    def __init__(self):
        self.users: Set[str] = set()
        self.resources: Set[str] = set()
        self.operations: Set[str] = set()
        self.user_attributes: Dict[str, Set[str]] = {{}}
        self.resource_attributes: Dict[str, Set[str]] = {{}}
        self.du: Dict[Tuple[str, str], str] = {{}}
        self.dr: Dict[Tuple[str, str], str] = {{}}
        self.UP: Set[Tuple[str, str, str]] = set()
        self.freq: Dict[Tuple[str, str, str], float] = {{}}
        self._coverage_cache = {{}}
        self._quality_cache = {{}}


        # Enhanced metrics for better rule generation
        self.attribute_frequency: Dict[str, int] = defaultdict(int)
        self.pattern_frequency: Dict[Tuple[str, str], int] = defaultdict(int)
        self.functional_dependencies: Dict[Tuple[str, str], Set[str]] = defaultdict(set)

    def rule_coverage_cached(self, rule):
        key = id(rule)
        if key not in self._coverage_cache:
            self._coverage_cache[key] = self.compute_rule_coverage_bucketed(rule)
        return self._coverage_cache[key]

    def rule_quality_cached(self, rule, uncovered_UP):
        key = (id(rule), tuple(sorted(uncovered_UP))[:50])  # coarse key; or omit uncovered in cache if using full UP
        if key not in self._quality_cache:
            self._quality_cache[key] = self.rule_quality(rule, uncovered_UP)
        return self._quality_cache[key]

    def invalidate_coverge(self, rule):
        self._coverage_cache.pop(id(rule), None)
        # quality cache can be left; it will be recomputed as needed    


    def load_data(self, users_data: Dict[str, Dict[str, str]],
                  resources_data: Dict[str, Dict[str, str]],
                  logs: List[Dict]):
        """Enhanced data loading with pattern and dependency analysis."""
        # Load user data
        for user, attrs in users_data.items():
            self.users.add(user)
            for attr, value in attrs.items():
                self.du[(user, attr)] = value
                if attr not in self.user_attributes:
                    self.user_attributes[attr] = set()
                self.user_attributes[attr].add(value)
                self.attribute_frequency[f"user_{{attr}}_{{value}}"] += 1

        # Load resource data
        for resource, attrs in resources_data.items():
            self.resources.add(resource)
            for attr, value in attrs.items():
                self.dr[(resource, attr)] = value
                if attr not in self.resource_attributes:
                    self.resource_attributes[attr] = set()
                self.resource_attributes[attr].add(value)
                self.attribute_frequency[f"resource_{{attr}}_{{value}}"] += 1

        # Process logs with enhanced pattern analysis
        log_counts = defaultdict(int)
        total_entries = 0

        for entry in logs:
            if entry.get('decision', '').lower() == 'allow':
                user = entry['user_name']
                resource = entry['object_name']
                operation = entry['action']

                self.operations.add(operation)
                log_counts[(user, resource, operation)] += 1
                total_entries += 1
                
                # Track patterns for better rule generation
                user_dept = self.du.get((user, 'department'), '')
                user_desig = self.du.get((user, 'designation'), '')
                res_type = self.dr.get((resource, 'type'), '')
                res_sens = self.dr.get((resource, 'sensitivity'), '')
                
                self.pattern_frequency[(user_dept, res_type)] += 1
                self.pattern_frequency[(user_desig, res_sens)] += 1
                
                # Track functional dependencies
                self.functional_dependencies[(user_dept, res_type)].add(operation)

        self.UP = set(log_counts.keys())
        self.freq = {{k: v/total_entries for k, v in log_counts.items()}}

    def rule_quality(self, rule: ABACRule, uncovered_UP: Set[Tuple[str, str, str]]) -> float:
        """
        Enhanced rule quality metric based on research findings:
        - Coverage ratio (35%)
        - True positive ratio (25%) 
        - Specificity score (15%)
        - Pattern frequency bonus (15%)
        - Constraint effectiveness (5%)
        - Over-assignment penalty (5%)
        """
        covered = self.compute_rule_coverage(rule) & uncovered_UP
        rule_coverage = self.compute_rule_coverage(rule)
        over_assignments = rule_coverage - self.UP

        if len(rule_coverage) == 0:
            return 0.0

        # Coverage metrics
        coverage_ratio = len(covered) / max(len(uncovered_UP), 1)
        true_positive_ratio = len(rule_coverage & self.UP) / max(len(rule_coverage), 1)
        
        # Specificity metrics
        specificity_score = 1.0 / max(rule.wsc(), 1)
        
        # Pattern frequency bonus (based on association rule mining)
        pattern_bonus = 0.0
        for u_attr, u_values in rule.user_expr.items():
            for r_attr, r_values in rule.resource_expr.items():
                for u_val in u_values:
                    for r_val in r_values:
                        pattern_key = (u_val, r_val)
                        if pattern_key in self.pattern_frequency:
                            pattern_bonus += min(self.pattern_frequency[pattern_key] / 10.0, 1.0)
        
        # Constraint effectiveness
        constraint_bonus = len(rule.constraints) * 0.1
        
        # Over-assignment penalty
        over_assignment_penalty = len(over_assignments) / max(len(rule_coverage), 1)
        
        # Wildcard penalty (rules that are too general)
        wildcard_penalty = 0.0
        total_attributes = len(self.user_attributes) + len(self.resource_attributes)
        if total_attributes > 0:
            expressed_ratio = (len(rule.user_expr) + len(rule.resource_expr)) / total_attributes
            if expressed_ratio < 0.1:  # Too few attributes expressed
                wildcard_penalty = 0.3
            elif expressed_ratio > 0.9:  # Too many attributes (overfitting)
                wildcard_penalty = 0.1

        # Weighted quality score
        quality = (
            coverage_ratio * 0.35 +           # Primary: coverage of uncovered permissions
            true_positive_ratio * 0.25 +     # Secondary: accuracy
            specificity_score * 0.15 +       # Tertiary: rule specificity
            pattern_bonus * 0.15 +           # Pattern frequency bonus
            constraint_bonus * 0.05 +        # Constraint effectiveness
            (1 - over_assignment_penalty) * 0.05  # Over-assignment penalty
        ) - wildcard_penalty

        return max(0.0, quality)


    def bucket_permissions(self):
        buckets = defaultdict(set)  # (type, sens, op) -> set of (u,r,op)
        for (u,r,o) in self.UP:
            t = self.dr.get((r,'type'))
            s = self.dr.get((r,'sensitivity'))
            buckets[(t,s,o)].add((u,r,o))
        return buckets

    def rules_per_bucket(self, buckets):
        rules=[]
        for (t,s,o), perms in buckets.items():
            users = {{u for (u,_,_) in perms}}
            res = {{r for (_,r,_) in perms}}
            # compute UAE/RAE
            uexpr = self.compute_UAE(users)
            rexpr = {{'type': {{t}}, 'sensitivity': {{s}}}}  # fix the bucket
            # prune UAE by specificity: keep only attrs with small value sets
            uexpr = {{a:v for a,v in uexpr.items() if len(v) <= max(3, len(self.user_attributes.get(a,[]))//4)}}
            if uexpr:
                rules.append(ABACRule(uexpr, rexpr, {{o}}, set()))
        return rules

    def bucket_fp(self, rule, bucket_perms):
        bucket_users = {{u for (u,_,_) in bucket_perms}}    
        bucket_res = {{r for (_,r,_) in bucket_perms}}
        fp=0; tp=0
        for u in bucket_users:
            for r in bucket_res:
                for o in rule.operations:
                    sat = self.satisfies_rule(u,r,o,rule)
                    if sat and (u,r,o) in bucket_perms:
                        tp+=1
                    elif sat:
                        fp+=1
        return tp, fp


    def compute_rule_coverage(self, rule: ABACRule) -> Set[Tuple[str, str, str]]:
        """Compute which permissions are covered by this rule."""
        covered = set()
        for user in self.users:
            for resource in self.resources:
                for operation in self.operations:
                    if self.satisfies_rule(user, resource, operation, rule):
                        covered.add((user, resource, operation))
        return covered

    def satisfies_rule(self, user: str, resource: str, operation: str, rule: ABACRule) -> bool:
        """Check if a permission satisfies the rule."""
        # Check user attribute expression
        for attr, values in rule.user_expr.items():
            if (user, attr) in self.du:
                if self.du[(user, attr)] not in values:
                    return False
            else:
                return False

        # Check resource attribute expression
        for attr, values in rule.resource_expr.items():
            if (resource, attr) in self.dr:
                if self.dr[(resource, attr)] not in values:
                    return False
            else:
                return False

        # Check operations
        if operation not in rule.operations:
            return False

        # Check constraints
        for constraint in rule.constraints:
            if not self.satisfies_constraint(user, resource, constraint):
                return False

        return True

    def satisfies_constraint(self, user: str, resource: str, constraint: str) -> bool:
        """Check constraint satisfaction."""
        if " = " in constraint:
            u_attr, r_attr = constraint.split(" = ")
            return (self.du.get((user, u_attr)) == self.dr.get((resource, r_attr)))
        return True

    def mine_abac_policy(self) -> List[ABACRule]:
        """
        Enhanced policy mining with multiple phases:
        1. Pattern-based rule generation
        2. Functional dependency discovery
        3. Association rule mining
        4. Individual permission coverage
        """
        rules = []
        uncovered_UP = set(self.UP)
        
        print(f"Starting enhanced policy mining with {{len(uncovered_UP)}} uncovered permissions")

        # Phase 1: Pattern-based rule generation
        print("Phase 1: Pattern-based rule generation")
        pattern_rules = self.generate_pattern_based_rules(uncovered_UP)
        rules.extend(pattern_rules)
        
        # Phase 2: Functional dependency discovery (ABAC-SRM approach)
        print("Phase 2: Functional dependency discovery")
        fd_rules = self.generate_functional_dependency_rules(uncovered_UP)
        rules.extend(fd_rules)
        
        # Phase 3: Association rule mining
        print("Phase 3: Association rule mining")
        assoc_rules = self.generate_association_rules(uncovered_UP)
        rules.extend(assoc_rules)
        
        # Phase 4: Individual permission coverage
        if uncovered_UP:
            print(f"Phase 4: Individual coverage for {{len(uncovered_UP)}} remaining permissions")
            individual_rules = self.generate_individual_rules(uncovered_UP)
            rules.extend(individual_rules)

        # Enhanced post-processing
        print("Post-processing: Merging, simplifying, and selecting rules")
        self.merge_rules(rules)
        self.simplify_rules(rules)
        final_rules = self.select_quality_rules(rules)

        print(f"Enhanced policy mining complete: {{len(final_rules)}} final rules")
        return final_rules

    def generate_pattern_based_rules(self, uncovered_UP: Set[Tuple[str, str, str]]) -> List[ABACRule]:
        """Generate rules based on frequent patterns."""
        rules = []
        max_iterations = min(len(uncovered_UP) * 2, 200)
        iteration = 0
        
        while uncovered_UP and iteration < max_iterations:
            iteration += 1
            
            # Select best seed based on pattern frequency
            seed_tuple = self.select_pattern_based_seed(uncovered_UP)
            if not seed_tuple:
                break
                
            u, r, o = seed_tuple
            cc = self.candidate_constraints(u, r)
            
            # Generate rules for similar users, resources, and operations
            res_type = self.dr.get((r,'type'))
            res_sens = self.dr.get((r,'sensitivity'))
            sr = {{x for x in self.resources if self.dr.get((x,'type')) == res_type and self.dr.get((x,'sensitivity')) == res_sens}}
            su = self.find_similar_users_pattern(u, r, o, cc)
            if len(su) >= 1:
                rule = self.create_rule(su, sr, {{o}}, cc)
                if rule:
                    rules.append(rule)
                    covered = self.compute_rule_coverage(rule) & uncovered_UP
                    uncovered_UP.difference_update(covered)
            
            uncovered_UP.discard(seed_tuple)
        
        return rules

    def generate_functional_dependency_rules(self, uncovered_UP: Set[Tuple[str, str, str]]) -> List[ABACRule]:
        """Generate rules based on functional dependencies (ABAC-SRM approach)."""
        rules = []
        
        # Find functional dependencies
        for (dept, res_type), operations in self.functional_dependencies.items():
            if len(operations) >= 2:  # Multiple operations for same pattern
                # Find users and resources matching this pattern
                matching_users = {{u for u in self.users if self.du.get((u, 'department')) == dept}}
                matching_resources = {{r for r in self.resources if self.dr.get((r, 'type')) == res_type}}
                
                if matching_users and matching_resources:
                    rule = self.create_rule(matching_users, matching_resources, operations, set())
                    if rule:
                        rules.append(rule)
        
        return rules

    def generate_association_rules(self, uncovered_UP: Set[Tuple[str, str, str]]) -> List[ABACRule]:
        """Generate rules using association rule mining techniques."""
        rules = []
        
        # Find frequent itemsets
        frequent_patterns = self.find_frequent_patterns()
        
        for pattern, support in frequent_patterns.items():
            if support >= 3:  # Minimum support threshold
                users, resources, operations = self.extract_pattern_components(pattern)
                if users and resources and operations:
                    rule = self.create_rule(users, resources, operations, set())
                    if rule:
                        rules.append(rule)
        
        return rules

    def generate_individual_rules(self, uncovered_UP: Set[Tuple[str, str, str]]) -> List[ABACRule]:
        """Generate individual rules for remaining permissions."""
        rules = []
        
        for u, r, o in list(uncovered_UP):
            user_expr = self.compute_UAE({{u}})
            resource_expr = self.compute_RAE({{r}})
            cc = self.candidate_constraints(u, r)
            
            rule = ABACRule(user_expr, resource_expr, {{o}}, cc)
            rules.append(rule)
        
        return rules

    def create_rule(self, users: Set[str], resources: Set[str], operations: Set[str], constraints: Set[str]) -> Optional[ABACRule]:
        """Create a rule from components."""
        user_expr = self.prune_uninformative(self.compute_UAE(users), True)
        resource_expr = self.prune_uninformative(self.compute_RAE(resources), False)
        
        if not user_expr or not resource_expr:
            return None
            
        return ABACRule(user_expr, resource_expr, operations, constraints)

    def compute_UAE(self, users_subset: Set[str]) -> Dict[str, Set[str]]:
        """Compute User Attribute Expression."""
        if not users_subset:
            return {{}}
        
        uae = {{}}
        for attr in self.user_attributes:
            values = set()
            for user in users_subset:
                if (user, attr) in self.du:
                    values.add(self.du[(user, attr)])
            if values:
                uae[attr] = values
        return uae

    def compute_RAE(self, resources_subset: Set[str]) -> Dict[str, Set[str]]:
        """Compute Resource Attribute Expression."""
        if not resources_subset:
            return {{}}
        
        rae = {{}}
        for attr in self.resource_attributes:
            values = set()
            for resource in resources_subset:
                if (resource, attr) in self.dr:
                    values.add(self.dr[(resource, attr)])
            if values:
                rae[attr] = values
        return rae

    def prune_uninformative(self, expr, is_user):
        space = self.user_attributes if is_user else self.resource_attributes
        return {{a: v for a, v in expr.items() if a in space and v and v != space[a]}}



    def candidate_constraints(self, user: str, resource: str) -> Set[str]:
        """Find candidate constraints."""
        # constraints = set()
        
        # # Equality constraints
        # for u_attr in self.user_attributes:
        #     for r_attr in self.resource_attributes:
        #         if ((user, u_attr) in self.du and (resource, r_attr) in self.dr and
        #             self.du[(user, u_attr)] == self.dr[(resource, r_attr)]):
        #             constraints.add(f"{{u_attr}} = {{r_attr}}")
        
        # return constraints
        cons = set()
        u_attrs = {{a for a in self.user_attributes if (user, a) in self.du}}
        r_attrs = {{a for a in self.resource_attributes if (resource, a) in self.dr}}
        for a in u_attrs & r_attrs:
            if self.du[(user,a)] == self.dr[(resource,a)]:
                cons.add(f"{{a}} = {{a}}")
        return cons

    def select_pattern_based_seed(self, uncovered_UP: Set[Tuple[str, str, str]]) -> Optional[Tuple[str, str, str]]:
        """Select seed based on pattern frequency."""
        best_seed = None
        best_score = -1
        
        for u, r, o in uncovered_UP:
            score = 0
            
            # Pattern frequency score
            user_dept = self.du.get((u, 'department'), '')
            res_type = self.dr.get((r, 'type'), '')
            pattern_score = self.pattern_frequency.get((user_dept, res_type), 0)
            
            # Similarity score
            similar_users = sum(1 for u2 in self.users if (u2, r, o) in self.UP)
            similar_ops = sum(1 for op2 in self.operations if (u, r, op2) in self.UP)
            similar_resources = sum(1 for r2 in self.resources if (u, r2, o) in self.UP)
            
            score = pattern_score + similar_users + similar_ops + similar_resources
            
            if score > best_score:
                best_score = score
                best_seed = (u, r, o)
        
        return best_seed

    def find_similar_users_pattern(self, u: str, r: str, o: str, cc: Set[str]) -> Set[str]:
        """Find similar users based on patterns."""
        similar_users = {{u}}
        
        for u_prime in self.users:
            if u_prime != u and (u_prime, r, o) in self.UP:
                cc_prime = self.candidate_constraints(u_prime, r)
                if cc == cc_prime or len(cc & cc_prime) > 0:
                    similar_users.add(u_prime)
        
        return similar_users

    def find_frequent_patterns(self) -> Dict[Tuple[str, str, str], int]:
        """Find frequent patterns using association rule mining."""
        patterns = defaultdict(int)
        
        for u, r, o in self.UP:
            user_dept = self.du.get((u, 'department'), '')
            user_desig = self.du.get((u, 'designation'), '')
            res_type = self.dr.get((r, 'type'), '')
            res_sens = self.dr.get((r, 'sensitivity'), '')
            
            # Create pattern combinations
            patterns[(user_dept, res_type, o)] += 1
            patterns[(user_desig, res_sens, o)] += 1
            patterns[(user_dept, user_desig, o)] += 1
        
        return dict(patterns)

    def extract_pattern_components(self, pattern: Tuple[str, str, str]) -> Tuple[Set[str], Set[str], Set[str]]:
        """Extract users, resources, and operations from pattern."""
        val1, val2, operation = pattern
        users = {{u for u in self.users if self.du.get((u,'department')) == val1}}
        if not users:
            users = {{u for u in self.users if self.du.get((u,'designation')) == val1}}
        resources = {{r for r in self.resources if self.dr.get((r,'type')) == val2}}
        if not resources:
            resources = {{r for r in self.resources if self.dr.get((r,'sensitivity')) == val2}}
        return users, resources, {{operation}}

    def merge_rules(self, rules: List[ABACRule]):
        """Enhanced rule merging."""
        initial_count = len(rules)
        merged = True
        max_merge_iterations = 100
        iteration = 0
        while merged and len(rules) > 1:
            merged = False
            for i in range(len(rules) - 1, -1, -1):
                for j in range(i - 1, -1, -1):
                    if self.can_merge_rules(rules[i], rules[j]):
                        merged_rule = self.merge_two_rules(rules[i], rules[j])
                        iteration += 1
                        if self.is_merge_beneficial(rules[i], rules[j], merged_rule):
                            rules[j] = merged_rule
                            rules.pop(i)
                            merged = True
                            break
                    if iteration >= max_merge_iterations:break
                if merged:
                    break
        
        print(f"Enhanced merging: {{initial_count - len(rules)}} rules merged")

    def can_merge_rules(self, rule1: ABACRule, rule2: ABACRule) -> bool:
        """Check if rules can be merged."""
        return (rule1.operations == rule2.operations and 
                rule1.constraints == rule2.constraints)

    def merge_two_rules(self, rule1: ABACRule, rule2: ABACRule) -> ABACRule:
        """Merge two compatible rules."""
        merged_user_expr = {{}}
        for attr in set(rule1.user_expr.keys()) | set(rule2.user_expr.keys()):
            vals = rule1.user_expr.get(attr, set()) | rule2.user_expr.get(attr, set())
            if vals:
                merged_user_expr[attr] = vals
        
        merged_resource_expr = {{}}
        for attr in set(rule1.resource_expr.keys()) | set(rule2.resource_expr.keys()):
            vals = rule1.resource_expr.get(attr, set()) | rule2.resource_expr.get(attr, set())
            if vals:
                merged_resource_expr[attr] = vals
        
        return ABACRule(merged_user_expr, merged_resource_expr, rule1.operations, rule1.constraints)

    def is_merge_beneficial(self, rule1: ABACRule, rule2: ABACRule, merged_rule: ABACRule) -> bool:
        """Check if merging is beneficial."""
        cov1 = self.rule_coverage_cached(rule1)
        cov2 = self.rule_coverage_cached(rule2)

        # Ensure merged coverage is computed once
        self.invalidate_coverge(merged_rule)  # safety: new object, but in case of reuse
        cov_m = self.rule_coverage_cached(merged_rule)

        coverage1 = cov1 & self.UP
        coverage2 = cov2 & self.UP
        coverage_merged = cov_m & self.UP

        true_positives_union = coverage1 | coverage2
        false_positives_merged = cov_m - self.UP

        return (coverage_merged.issuperset(true_positives_union) and
                len(false_positives_merged) <= len(true_positives_union) + 3)

    def simplify_rules(self, rules: List[ABACRule]):
        """Enhanced rule simplification."""
        if not rules:
            return

        initial_count = len(rules)
        filtered_rules = []
        
        for rule in rules:
            coverage = self.rule_coverage_cached(rule)
            true_positives = coverage & self.UP
            false_positives = coverage - self.UP
            
            # Skip rules with no true positives
            if not true_positives:
                continue
            
            # Skip rules with too many false positives
            if len(false_positives) > len(true_positives) * 2:
                continue
            
            # # Skip overly general rules
            # if self.UP and len(true_positives) / len(self.UP) > 0.9:
            #     continue
            
            # Skip rules with too few attributes
            total_attrs = len(self.user_attributes) + len(self.resource_attributes)
            if total_attrs > 0:
                expressed_ratio = (len(rule.user_expr) + len(rule.resource_expr)) / total_attrs
                if expressed_ratio < 0.02:  # Less than 5% attributes expressed
                    continue
            
            filtered_rules.append(rule)
        
        rules.clear()
        rules.extend(filtered_rules)
        print(f"Enhanced simplification: {{initial_count - len(rules)}} rules removed")

    def compute_rule_coverage_bucketed(self, rule):
        # If rule fixes resource type/sensitivity
        tset = rule.resource_expr.get('type'); sset = rule.resource_expr.get('sensitivity')
        if tset and sset and len(tset)==1 and len(sset)==1:
            t = next(iter(tset)); s = next(iter(sset))
            resources = [r for r in self.resources if self.dr.get((r,'type'))==t and self.dr.get((r,'sensitivity'))==s]
        else:
            resources = self.resources
        covered = set()
        for user in self.users:
            for resource in resources:
                for operation in rule.operations:
                    if self.satisfies_rule(user, resource, operation, rule):
                        covered.add((user, resource, operation))
        return covered



    def select_quality_rules(self, rules: List[ABACRule]) -> List[ABACRule]:
        if not rules:
            return rules

        # 1) Score rules
        rule_scores = []
        for rule in rules:
            quality = self.rule_quality(rule, set(self.UP))
            coverage = self.compute_rule_coverage(rule) & self.UP
            rule_scores.append((rule, quality, len(coverage)))

        # Sort by quality
        rule_scores.sort(key=lambda x: x[1], reverse=True)

        selected_rules = []
        covered_permissions = set()
        remaining_permissions = set(self.UP)

        # Helper to add rule if it brings new coverage
        def add_rule_if_new_coverage(rule, min_quality=0.05):
            quality = self.rule_quality(rule, set(self.UP))
            if quality < min_quality:
                return False
            rule_coverage = self.compute_rule_coverage(rule) & self.UP
            new_coverage = rule_coverage - covered_permissions
            if not new_coverage:
                return False
            selected_rules.append(rule)
            covered_permissions.update(rule_coverage)
            return True

        # 2) Bucket-first seeding: pick best one per (type,sensitivity,ops) bucket
        bucket_key = lambda r: (
            tuple(sorted(r.resource_expr.get('type', []))),
            tuple(sorted(r.resource_expr.get('sensitivity', []))),
            tuple(sorted(r.operations)),
        )
        by_bucket = defaultdict(list)
        for (rule, q, c) in rule_scores:
            by_bucket[bucket_key(rule)].append((rule, q, c))

        for key, lst in by_bucket.items():
            lst.sort(key=lambda x: x[1], reverse=True)
            r, q, c = lst[0]
            add_rule_if_new_coverage(r)

        # 3) Continue with the remaining sorted rules (greedy)
        for rule, quality, coverage_size in rule_scores:
            if rule in selected_rules:
                continue
            if add_rule_if_new_coverage(rule, min_quality=0.05):
                if len(covered_permissions) / len(self.UP) >= 0.95:
                    break

        # 4) Optional: fallback for any remaining
        remaining_permissions = self.UP - covered_permissions
        if remaining_permissions:
            print(f"Adding fallback rules for {{len(remaining_permissions)}} remaining permissions")
            for rule, quality, coverage_size in rule_scores:
                if rule in selected_rules:
                    continue
                if add_rule_if_new_coverage(rule, min_quality=0.02):
                    if len(selected_rules) >= 40:
                        break

        print(f"Enhanced selection: {{len(selected_rules)}} rules selected")
        if len(self.UP) > 0:
            print(f"Coverage: {{len(covered_permissions)}}/{{len(self.UP)}} permissions ({{len(covered_permissions)/len(self.UP)*100:.1f}}%)")
        return selected_rules


def parse_data_file(file_content: str, file_type: str) -> Union[Dict, List]:
    """
    Parses the content of a data file based on its type ('user', 'resource', or 'log').

    Args:
        file_content (str): The entire content of the file as a string.
        file_type (str): The type of the file, can be 'user', 'resource', or 'log'.

    Returns:
        Union[Dict, List]:
            - For 'user' or 'resource': A dictionary where keys are entity names
              and values are dictionaries of their attributes.
              Example: {{"alice": {{"department": "Finance"}}, ...}}
            - For 'log': A list of dictionaries, each representing a log entry.
              Example: [{{'user_name': 'alice', 'object_name': 'budget_2024', ...}}, ...]
    """
    if file_type in ['user', 'resource']:
        result: Dict[str, Dict[str, str]] = {{}}
    elif file_type == 'log':
        result: List[Dict[str, str]] = {{}}
    else:
        raise ValueError(f"Unsupported file_type: {{file_type}}. Expected 'user', 'resource', or 'log'.")

    for line_num, line in enumerate(file_content.splitlines(), 1):
        stripped_line = line.strip()

        # Ignore comments and blank lines
        if not stripped_line or stripped_line.startswith('#'):
            continue

        # Handle '<' and '>' characters
        if stripped_line.startswith('<') and stripped_line.endswith('>'):
            clean_line = stripped_line[1:-1].strip()
        else:
            print(f"Warning: Line {{line_num}} in '{{file_type}}' file is malformed (missing '<' or '>'): '{{stripped_line}}'. Skipping.")
            continue

        if not clean_line:
            continue # Line might become empty after stripping < >

        tokens = clean_line.split()

        if not tokens:
            print(f"Warning: Line {{line_num}} in '{{file_type}}' file is empty after cleaning. Skipping.")
            continue

        try:
            if file_type in ['user', 'resource']:
                # Format: <name key1:value1 key2:value2 ...>
                entity_name = tokens[0]
                attributes: Dict[str, str] = {{}}
                for token in tokens[1:]:
                    if ':' in token:
                        key, value = token.split(':', 1)
                        attributes[key.strip()] = value.strip()
                    else:
                        print(f"Warning: Line {{line_num}} in '{{file_type}}' file contains malformed attribute '{{token}}'. Skipping attribute.")
                result[entity_name] = attributes
            elif file_type == 'log':
                # Format: <user resource op time decision>
                if len(tokens) == 5:
                    log_entry = {{
                        'user_name': tokens[0],
                        'object_name': tokens[1],
                        'action': tokens[2],
                        'time': tokens[3],
                        'decision': tokens[4]
                    }}
                    result.append(log_entry)
                else:
                    print(f"Warning: Line {{line_num}} in '{{file_type}}' file has incorrect number of fields ({{len(tokens)}} instead of 5): '{{clean_line}}'. Skipping.")
        except Exception as e:
            print(f"Warning: Error parsing line {{line_num}} in '{{file_type}}' file: '{{clean_line}}'. Error: {{e}}. Skipping.")

    return result

def read_file_content(filename: str) -> str:
    """Reads the entire content of a file and handles potential errors."""
    try:
        with open(filename, 'r') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: The file '{{filename}}' was not found. Please ensure it is in the correct directory.")
        return "" # Return empty string if file is not found


def main():
    """Main function to orchestrate the ABAC policy mining process."""
    # 1. Define fixed filenames
    users_filename = "user.txt"
    resources_filename = "object.txt"
    logs_filename = "logs.txt"

    # 3. Read the content of each file
    print("--- Step 1: Reading data files ---")
    user_file_content = read_file_content(users_filename)
    resource_file_content = read_file_content(resources_filename)
    log_file_content = read_file_content(logs_filename)

    if not all([user_file_content, resource_file_content, log_file_content]):
        print("Aborting due to missing file content.")
        return

    # 4. Parse the raw data using the `parse_data_file` function
    print("\n--- Step 2: Parsing raw data ---")
    users_data = parse_data_file(user_file_content, file_type='user')
    resources_data = parse_data_file(resource_file_content, file_type='resource')
    logs = parse_data_file(log_file_content, file_type='log')
    
    if not users_data or not resources_data or not logs:
        print("Aborting due to empty or malformed parsed data.")
        return

    print(f"Parsing complete: {{len(users_data)}} users, {{len(resources_data)}} resources, and {{len(logs)}} log entries processed.")

    # 5. Instantiate the miner and load data
    print("\n--- Step 3: Running the ABAC Policy Miner ---")
    miner = ABACPolicyMiner()
    miner.load_data(users_data, resources_data, logs)
    
    # Check if any UP (allowed permissions) exist before mining
    if not miner.UP:
        print("No 'Allow' log entries found. Cannot mine ABAC policy. Please check logs.txt.")
        return

    # 6. Mine the ABAC policy
    final_rules = miner.mine_abac_policy()
    print("Policy mining complete.")

    # 7. Print the final results
    print(f"\n--- Generated {{len(final_rules)}} ABAC Rules ---")
    if not final_rules:
        print("No robust rules were generated based on the provided logs that passed quality checks.")
    else:
        for i, rule in enumerate(final_rules, 1):
            print(f"\nRule {{i}}: {{rule}}")
            print(f"  WSC (Complexity): {{rule.wsc()}}")
            
            coverage_percentage = 0.0
            if miner.UP:
                # Calculate true positives covered by this specific rule
                rule_coverage_up = miner.compute_rule_coverage(rule) & miner.UP
                coverage_percentage = (len(rule_coverage_up) / len(miner.UP)) * 100
            print(f"  Approx. True Positive Coverage: {{coverage_percentage:.2f}}% of total allowed permissions.")

if __name__ == "__main__":
    main()

**Final Instruction**
Provide ONLY the complete, self-contained Python code for the parse_data_file function, including necessary imports like typing. Do not include any example usage or explanations outside of the code's docstrings and comments.
    '''
    
    try:
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(rules_prompt)
        
        script_content = response.text.strip()
        
        # Extract script if it's wrapped in code blocks
        if '```python' in script_content:
            start = script_content.find('```python') + 9
            end = script_content.rfind('```')
            if end > start:
                script_content = script_content[start:end].strip()
        elif '```' in script_content:
            start = script_content.find('```') + 3
            end = script_content.rfind('```')
            if end > start:
                script_content = script_content[start:end].strip()
        
        # Count lines and dependencies
        lines = script_content.split('\n')
        line_count = len([line for line in lines if line.strip()])
        
        # Extract dependencies from imports
        dependencies = []
        for line in lines:
            if line.strip().startswith('import ') or line.strip().startswith('from '):
                if 'pandas' in line:
                    dependencies.append('pandas')
                elif 'numpy' in line:
                    dependencies.append('numpy')
                elif 're' in line:
                    dependencies.append('re')
                elif 'typing' in line:
                    dependencies.append('typing')
                elif 'collections' in line:
                    dependencies.append('collections')
        
        dependencies = list(set(dependencies)) if dependencies else ['pandas', 're', 'typing', 'collections']
        
        return {
            'script_content': script_content,
            'line_count': line_count,
            'dependencies': ', '.join(dependencies),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'script_filename': 'abac_rules_generator.py'
        }
        
    except Exception as e:
        return {
            'error': f"An error occurred while generating the rules script: {e}",
            'script_content': '',
            'line_count': 0,
            'dependencies': '',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'script_filename': 'abac_rules_generator.py'
        }