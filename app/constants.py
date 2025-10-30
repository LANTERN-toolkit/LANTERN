# /app/constants.py

DEFAULT_RULE_PRINCIPLES = """
1. **Comprehensive Evidence Analysis:** Analyze every Allow entry in the log data systematically. Each entry represents a valid access pattern that must be captured by at least one rule.
2. **Multi-Level Pattern Recognition:** Extract rules at multiple levels of specificity:
   - **Exact Match Rules:** Direct user-object-action combinations from logs
   - **Attribute-Based Patterns:** Generalize based on user attributes (department, designation) and object attributes (type, sensitivity)
   - **Cross-Pattern Analysis:** Look for common access patterns across different users or objects that suggest broader organizational rules
3. **Hierarchical and Peer Inference:**
   - If junior roles have access, senior roles in the same department inherit at least the same permissions
   - If multiple users in the same designation/department access similar resources, generalize to role-based rules
   - If users from different departments access the same resource, identify if it's a system-wide permission
4. **Complete Coverage Validation:**
   - **Mandatory:** Every single Allow log entry must be explainable by at least one extracted rule
   - **Cross-Reference Check:** After generating rules, mentally verify each log entry against your rule set
   - **Gap Analysis:** If any log entry cannot be explained, create additional rules to cover it
5. **Context-Aware Generalization:**
   - Consider the action type (read/write/execute) when generalizing - some actions may be role-specific while others are universal
   - Factor in object sensitivity levels - access to low-sensitivity items may follow different patterns than high-sensitivity items
   - Account for department alignment - users typically have broader access to their own department's resources
6. **Overlapping Rule Strategy:** Rather than creating mutually exclusive rules, allow for overlapping rules that ensure comprehensive coverage. It's better to have redundant coverage than missed permissions.
7. **Edge Case Inclusion:** Pay special attention to:
   - Cross-departmental access (users accessing resources outside their department)
   - Unusual combinations of user attributes and object types
   - High-privilege actions (write, execute) that may indicate special roles or system requirements
8. **Prioritize Specificity:** To avoid false positives, prefer more specific rules over highly general ones. For example, if only "Managers" can write, create a rule for "Managers" specifically, not a rule for department="*" that might accidentally include them. A rule that matches a "Denied Access Pattern" is incorrect.
"""