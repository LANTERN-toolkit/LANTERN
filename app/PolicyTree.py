# Place this code in app/services.py

class TreeNode:
    """
    Represents a single node in our Policy Decision Tree. Each node can have
    multiple children and can terminate a rule by holding a decision.
    """
    def __init__(self):
        """
        Initializes a new tree node.
        """
        # A dictionary to hold child nodes, keyed by attribute value (e.g., 'Sales', 'Manager', '*')
        self.children = {}
        # The decision ('Permit' or 'Deny') if a rule path ends at this node.
        self.decision = None
        # The original text of the rule for explainability.
        self.rule_text = None

class PolicyTree:
    """
    The main data structure that builds a tree from a set of rules and can
    efficiently verify log entries against that policy.
    """
    def __init__(self, attributes_order: list):
        """
        Initializes the policy tree.
        
        Args:
            attributes_order (list): A list of strings defining the order of attributes
                                     that constitutes the hierarchy of the tree.
                                     Example: ['department', 'designation', 'action', 'type', 'sensitivity']
        """
        self.root = TreeNode()
        # The order of attributes is crucial for consistent building and traversal.
        self.attributes_order = attributes_order

    def add_rule(self, rule: dict):
        """
        Adds a single, parsed rule dictionary to the tree.
        
        Args:
            rule (dict): A dictionary representing a single rule.
                         Example: {'decision': 'Permit', 'department': 'Finance',
                                   'action': 'read', 'original_text': '...'}
        """
        
        if rule.get('decision') != 'Permit':
            print(f"Skipping non-Permit rule: {rule.get('decision')}")
            return 

        print(f"Adding rule: {rule}")
        node = self.root
        for attribute in self.attributes_order:
            # If the rule specifies a value for this attribute, use it.
            # Otherwise, use the wildcard value '*' to represent "any".
            value = rule.get(attribute, '*')
            
            # If a path for this value doesn't exist, create it.
            if value not in node.children:
                node.children[value] = TreeNode()
            
            # Move down the tree.
            node = node.children[value]
            
        # The final node in the path holds the decision and the original rule text.
        node.decision = rule.get('decision')
        node.rule_text = rule.get('original_text')
        print(f"Successfully added rule ending at node with decision: {node.decision}")

    def verify_log(self, log_entry: dict) -> tuple[str, str | None]:
        """
        Verifies a log entry against the policy tree, finding the most specific matching rule.
        
        Args:
            log_entry (dict): A dictionary representing a single, enriched log event.
            
        Returns:
            tuple: A tuple containing the decision ('Permit' or 'Deny') and the
                   text of the rule that was matched (or None).
        """
        
        # This will store the best match we find during traversal.
        # Specificity score helps decide which rule wins if multiple rules match.
        best_match = {'decision': None, 'rule_text': None, 'specificity': -1}

        def find_match(node: TreeNode, depth: int, current_specificity: int):
            """A recursive helper function to traverse the tree and find the best match."""
            nonlocal best_match

            # A rule path terminates at a node with a decision.
            # If this rule is more specific than the best one we've found so far, it becomes the new best match.
            if node.decision and current_specificity > best_match['specificity']:
                best_match = {
                    'specificity': current_specificity,
                    'decision': node.decision,
                    'rule_text': node.rule_text
                }

            # Stop traversing if we've gone through all attributes.
            if depth >= len(self.attributes_order):
                return

            attribute_to_check = self.attributes_order[depth]
            log_value = log_entry.get(attribute_to_check)

            # --- The Core Logic: Check both specific and wildcard paths ---

            # 1. Traverse the specific path (e.g., 'Finance', 'Manager').
            #    A match on a specific path is better, so we increment the specificity score.
            if log_value and log_value in node.children:
                find_match(node.children[log_value], depth + 1, current_specificity + 1)

            # 2. Traverse the wildcard path ('*').
            #    A match on a wildcard path is less specific, so we do NOT increment the score.
            if '*' in node.children:
                find_match(node.children['*'], depth + 1, current_specificity)

        # Start the recursive search from the root of the tree.
        find_match(self.root, 0, 0)
        
        # If no rule was matched at all, the implicit/default decision is 'Deny'.
        return best_match['decision'] or 'Deny', best_match['rule_text']