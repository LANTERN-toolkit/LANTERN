from typing import Dict, Set, List, Tuple, Optional, Union
from collections import defaultdict
import copy
import time
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
        return f"⟨User_Expr: {self.user_expr}, Resource_Expr: {self.resource_expr}, Operations: {self.operations}, Constraints: {self.constraints}⟩"

class ABACPolicyMiner:
    """Enhanced ABAC Policy Miner with research-based improvements."""
    
    def __init__(self):
        self.users: Set[str] = set()
        self.resources: Set[str] = set()
        self.operations: Set[str] = set()
        self.user_attributes: Dict[str, Set[str]] = {}
        self.resource_attributes: Dict[str, Set[str]] = {}
        self.du: Dict[Tuple[str, str], str] = {}
        self.dr: Dict[Tuple[str, str], str] = {}
        self.UP: Set[Tuple[str, str, str]] = set()
        self.freq: Dict[Tuple[str, str, str], float] = {}
        self._coverage_cache = {}
        self._quality_cache = {}


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
                self.attribute_frequency[f"user_{attr}_{value}"] += 1

        # Load resource data
        for resource, attrs in resources_data.items():
            self.resources.add(resource)
            for attr, value in attrs.items():
                self.dr[(resource, attr)] = value
                if attr not in self.resource_attributes:
                    self.resource_attributes[attr] = set()
                self.resource_attributes[attr].add(value)
                self.attribute_frequency[f"resource_{attr}_{value}"] += 1

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
                
                # Track patterns for better rule generation - dynamic attribute handling
                self._track_patterns_dynamic(user, resource, operation)

        self.UP = set(log_counts.keys())
        self.freq = {k: v/total_entries for k, v in log_counts.items()}

    def _track_patterns_dynamic(self, user: str, resource: str, operation: str):
        """Track patterns dynamically based on available attributes."""
        # Get all user and resource attribute values
        user_attrs = {attr: self.du.get((user, attr), '') for attr in self.user_attributes}
        resource_attrs = {attr: self.dr.get((resource, attr), '') for attr in self.resource_attributes}
        
        # Track patterns between user and resource attributes
        for u_attr, u_val in user_attrs.items():
            for r_attr, r_val in resource_attrs.items():
                if u_val and r_val:  # Only track non-empty values
                    self.pattern_frequency[(u_val, r_val)] += 1
                    self.functional_dependencies[(u_val, r_val)].add(operation)
        
        # Track patterns within user attributes
        user_values = [v for v in user_attrs.values() if v]
        for i in range(len(user_values)):
            for j in range(i+1, len(user_values)):
                self.pattern_frequency[(user_values[i], user_values[j])] += 1
        
        # Track patterns within resource attributes
        resource_values = [v for v in resource_attrs.values() if v]
        for i in range(len(resource_values)):
            for j in range(i+1, len(resource_values)):
                self.pattern_frequency[(resource_values[i], resource_values[j])] += 1

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
        
        # Side-balanced specificity metrics
        def _side_concentration(expr, space):
            if not space:
                return 1.0
            if not expr:
                return 0.0
            num = sum(len(v) for v in expr.values())
            den = sum(len(space.get(a, set())) for a in expr.keys()) or 1
            return 1.0 - (num / den)  # Fewer values per attr => higher concentration

        spec_user = _side_concentration(rule.user_expr, self.user_attributes)
        spec_res = _side_concentration(rule.resource_expr, self.resource_attributes)
        specificity_score = 0.5 * (spec_user + spec_res)
        
        # Pattern frequency bonus (based on association rule mining)
        pattern_bonus = 0.0
        for u_attr, u_values in rule.user_expr.items():
            for r_attr, r_values in rule.resource_expr.items():
                for u_val in u_values:
                    for r_val in r_values:
                        pattern_key = (u_val, r_val)
                        if pattern_key in self.pattern_frequency:
                            pattern_bonus += min(self.pattern_frequency[pattern_key] / 10.0, 1.0)
                            # Intra-side pattern reinforcement when one side lacks comparable attributes
        if len(self.resource_attributes) == 0 or len(rule.resource_expr) == 0:
            # Reward strong user-only patterns
            u_vals = set().union(*rule.user_expr.values()) if rule.user_expr else set()
            for x in u_vals:
                for y in u_vals:
                    if x < y and (x, y) in self.pattern_frequency:
                        pattern_bonus += min(self.pattern_frequency[(x, y)] / 10.0, 1.0) / 2.0

        if len(self.user_attributes) == 0 or len(rule.user_expr) == 0:
            # Reward strong resource-only patterns
            r_vals = set().union(*rule.resource_expr.values()) if rule.resource_expr else set()
            for x in r_vals:
                for y in r_vals:
                    if x < y and (x, y) in self.pattern_frequency:
                        pattern_bonus += min(self.pattern_frequency[(x, y)] / 10.0, 1.0) / 2.0        

        # Constraint effectiveness
        constraint_bonus = len(rule.constraints) * 0.1
        
        # Over-assignment penalty
        over_assignment_penalty = len(over_assignments) / max(len(rule_coverage), 1)
        
        # Wildcard penalty (rules that are too general)
# Wildcard penalty (rules that are too general) - side-normalized version
        wildcard_penalty = 0.0
        u_space = max(len(self.user_attributes), 1)
        r_space = max(len(self.resource_attributes), 1)
        u_ratio = len(rule.user_expr) / u_space
        r_ratio = len(rule.resource_expr) / r_space
        expr_ratio = 0.5 * (u_ratio + r_ratio)

        if expr_ratio < 0.10:
            wildcard_penalty = 0.30
        elif expr_ratio > 0.90:
            wildcard_penalty = 0.10

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
    
    def _top_resource_attrs_by_info(self, k=2):
        """Score resource attributes by entropy and return top k."""
        import math
        scores = []
        for attr, domain in self.resource_attributes.items():
            counts = {}
            for r in self.resources:
                v = self.dr.get((r, attr))
                if v is not None:
                    counts[v] = counts.get(v, 0) + 1
            total = sum(counts.values()) or 1
            p = [c/total for c in counts.values()]
            entropy = -sum(pi*math.log(pi+1e-12, 2) for pi in p) if p else 0.0
            scores.append((attr, entropy))
        scores.sort(key=lambda x: x[1], reverse=True)
        return [a for a, _ in scores[:k]]


    def bucket_permissions(self):
        """Dynamic bucketing based on available resource attributes."""
        buckets = defaultdict(set)
        
        # Use first two resource attributes for bucketing (or all if less than 2)
        resource_attrs = self._top_resource_attrs_by_info(k=2)
        if len(resource_attrs) >= 2:
            attr1, attr2 = resource_attrs[0], resource_attrs[1]
            for (u,r,o) in self.UP:
                val1 = self.dr.get((r, attr1))
                val2 = self.dr.get((r, attr2))
                buckets[(val1, val2, o)].add((u,r,o))
        elif len(resource_attrs) == 1:
            attr1 = resource_attrs[0]
            for (u,r,o) in self.UP:
                val1 = self.dr.get((r, attr1))
                buckets[(val1, None, o)].add((u,r,o))
        else:
            # No resource attributes, bucket by operation only
            for (u,r,o) in self.UP:
                buckets[(None, None, o)].add((u,r,o))
        
        return buckets

    def rules_per_bucket(self, buckets):
        """Generate rules for each bucket dynamically."""
        rules = []
        resource_attrs = list(self.resource_attributes.keys())
        
        for bucket_key, perms in buckets.items():
            users = {u for (u,_,_) in perms}
            res = {r for (_,r,_) in perms}
            
            # compute UAE/RAE
            uexpr = self.compute_UAE(users)
            
            # Create resource expression dynamically based on bucket key
            rexpr = {}
            if len(resource_attrs) >= 2:
                val1, val2, o = bucket_key
                if val1 is not None:
                    rexpr[resource_attrs[0]] = {val1}
                if val2 is not None:
                    rexpr[resource_attrs[1]] = {val2}
            elif len(resource_attrs) == 1:
                val1, _, o = bucket_key
                if val1 is not None:
                    rexpr[resource_attrs[0]] = {val1}
            else:
                _, _, o = bucket_key
            
            # prune UAE by specificity: keep only attrs with small value sets
            uexpr = {a:v for a,v in uexpr.items() if len(v) <= max(3, len(self.user_attributes.get(a,[]))//4)}
            if uexpr and rexpr:
                rules.append(ABACRule(uexpr, rexpr, {o}, set()))
        return rules

    def bucket_fp(self, rule, bucket_perms):
        bucket_users = {u for (u,_,_) in bucket_perms}
        bucket_res = {r for (_,r,_) in bucket_perms}
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
        
        print(f"Starting enhanced policy mining with {len(uncovered_UP)} uncovered permissions")

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
            print(f"Phase 4: Individual coverage for {len(uncovered_UP)} remaining permissions")
            individual_rules = self.generate_individual_rules(uncovered_UP)
            rules.extend(individual_rules)

        # Enhanced post-processing
        print("Post-processing: Merging, simplifying, and selecting rules")
        self.merge_rules(rules)
        self.simplify_rules(rules)
        final_rules = self.select_quality_rules(rules)

        print(f"Enhanced policy mining complete: {len(final_rules)} final rules")
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
            # Find resources with similar attributes dynamically
            sr = self._find_similar_resources_dynamic(r)
            su = self.find_similar_users_pattern(u, r, o, cc)
            if len(su) >= 1:
                rule = self.create_rule(su, sr, {o}, cc)
                if rule:
                    rules.append(rule)
                    covered = self.compute_rule_coverage(rule) & uncovered_UP
                    uncovered_UP.difference_update(covered)
            
            uncovered_UP.discard(seed_tuple)
        
        return rules

    def _find_similar_resources_dynamic(self, resource: str) -> Set[str]:
        """Find resources with similar attributes dynamically."""
        similar_resources = {resource}
        
        # Get all attribute values for the given resource
        resource_attrs = {attr: self.dr.get((resource, attr)) for attr in self.resource_attributes}
        
        # Find other resources with matching attribute values
        for other_resource in self.resources:
            if other_resource != resource:
                other_attrs = {attr: self.dr.get((other_resource, attr)) for attr in self.resource_attributes}
                
                # Check if resources share significant attribute values
                matching_attrs = sum(1 for attr in self.resource_attributes 
                                    if resource_attrs.get(attr) and resource_attrs.get(attr) == other_attrs.get(attr))
                
                # Consider resources similar if they share at least half of their attributes
                if matching_attrs >= len(self.resource_attributes) // 2:
                    similar_resources.add(other_resource)
        
        return similar_resources

    def generate_functional_dependency_rules(self, uncovered_UP: Set[Tuple[str, str, str]]) -> List[ABACRule]:
        """Generate rules based on functional dependencies (ABAC-SRM approach)."""
        rules = []
        
        # Find functional dependencies dynamically
        for (val1, val2), operations in self.functional_dependencies.items():
            if len(operations) >= 2:  # Multiple operations for same pattern
                # Find users and resources matching this pattern
                matching_users = set()
                matching_resources = set()
                
                # Try to match against user attributes
                for attr in self.user_attributes:
                    users_with_val = {u for u in self.users if self.du.get((u, attr)) == val1}
                    if users_with_val:
                        matching_users = users_with_val
                        break
                
                # Try to match against resource attributes
                for attr in self.resource_attributes:
                    resources_with_val = {r for r in self.resources if self.dr.get((r, attr)) == val2}
                    if resources_with_val:
                        matching_resources = resources_with_val
                        break
                
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
            user_expr = self.compute_UAE({u})
            resource_expr = self.compute_RAE({r})
            cc = self.candidate_constraints(u, r)
            
            rule = ABACRule(user_expr, resource_expr, {o}, cc)
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
            return {}
        
        uae = {}
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
            return {}
        
        rae = {}
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
        pruned = {}
        for a, vals in expr.items():
            if a not in space or not vals:
                continue
            domain = space[a]
            # Keep if not full domain OR if domain is small (still informative)
            if vals == domain:
                if len(domain) <= 3:  # Small domains are still informative
                    pruned[a] = vals
                continue
            pruned[a] = vals
        return pruned


    def candidate_constraints(self, user: str, resource: str) -> Set[str]:
        """Find candidate constraints."""
        # constraints = set()
        
        # # Equality constraints
        # for u_attr in self.user_attributes:
        #     for r_attr in self.resource_attributes:
        #         if ((user, u_attr) in self.du and (resource, r_attr) in self.dr and
        #             self.du[(user, u_attr)] == self.dr[(resource, r_attr)]):
        #             constraints.add(f"{u_attr} = {r_attr}")
        
        # return constraints
        cons = set()
        u_attrs = {a for a in self.user_attributes if (user, a) in self.du}
        r_attrs = {a for a in self.resource_attributes if (resource, a) in self.dr}
        for a in u_attrs & r_attrs:
            uval = self.du.get((user, a))
            rval = self.dr.get((resource, a))
            if uval is not None and rval is not None and uval == rval:
                cons.add(f"{a} = {a}")
        return cons

    def select_pattern_based_seed(self, uncovered_UP: Set[Tuple[str, str, str]]) -> Optional[Tuple[str, str, str]]:
        """Select seed based on pattern frequency."""
        best_seed = None
        best_score = -1
        
        for u, r, o in uncovered_UP:
            score = 0
            
            # Pattern frequency score - dynamic attribute handling
            user_attrs = {attr: self.du.get((u, attr), '') for attr in self.user_attributes}
            resource_attrs = {attr: self.dr.get((r, attr), '') for attr in self.resource_attributes}
            
            # Calculate pattern score based on all attribute combinations
            for u_val in user_attrs.values():
                for r_val in resource_attrs.values():
                    if u_val and r_val:
                        score += self.pattern_frequency.get((u_val, r_val), 0)
            
            # Similarity score
            similar_users = sum(1 for u2 in self.users if (u2, r, o) in self.UP)
            similar_ops = sum(1 for op2 in self.operations if (u, r, op2) in self.UP)
            similar_resources = sum(1 for r2 in self.resources if (u, r2, o) in self.UP)
            
            score += similar_users + similar_ops + similar_resources
            
            if score > best_score:
                best_score = score
                best_seed = (u, r, o)
        
        return best_seed

    def find_similar_users_pattern(self, u: str, r: str, o: str, cc: Set[str]) -> Set[str]:
        """Find similar users based on patterns."""
        similar_users = {u}
        
        for u_prime in self.users:
            if u_prime != u and (u_prime, r, o) in self.UP:
                cc_prime = self.candidate_constraints(u_prime, r)
                if cc == cc_prime or len(cc & cc_prime) > 0:
                    similar_users.add(u_prime)
        
        return similar_users

    def find_frequent_patterns(self) -> Dict[Tuple[str, str, str], int]:
        """Find frequent patterns using association rule mining - dynamic version."""
        patterns = defaultdict(int)
        
        for u, r, o in self.UP:
            # Get all user and resource attribute values
            user_attrs = {attr: self.du.get((u, attr), '') for attr in self.user_attributes}
            resource_attrs = {attr: self.dr.get((r, attr), '') for attr in self.resource_attributes}
            
            # Create pattern combinations dynamically
            user_values = [v for v in user_attrs.values() if v]
            resource_values = [v for v in resource_attrs.values() if v]
            
            # Cross-product of user and resource values with operation
            for u_val in user_values:
                for r_val in resource_values:
                    patterns[(u_val, r_val, o)] += 1
            
            # Within-user attribute combinations
            for i in range(len(user_values)):
                for j in range(i+1, len(user_values)):
                    patterns[(user_values[i], user_values[j], o)] += 1
            
            # Within-resource attribute combinations
            for i in range(len(resource_values)):
                for j in range(i+1, len(resource_values)):
                    patterns[(resource_values[i], resource_values[j], o)] += 1
        
        return dict(patterns)

    def extract_pattern_components(self, pattern: Tuple[str, str, str]) -> Tuple[Set[str], Set[str], Set[str]]:
        """Extract users, resources, and operations from pattern - dynamic version."""
        val1, val2, operation = pattern
        users = set()
        resources = set()
        
        # Try to match val1 against user attributes
        for attr in self.user_attributes:
            matching_users = {u for u in self.users if self.du.get((u, attr)) == val1}
            if matching_users:
                users = matching_users
                break
        
        # Try to match val2 against resource attributes
        for attr in self.resource_attributes:
            matching_resources = {r for r in self.resources if self.dr.get((r, attr)) == val2}
            if matching_resources:
                resources = matching_resources
                break
        
        # If no matches found, try reverse matching
        if not users:
            for attr in self.user_attributes:
                matching_users = {u for u in self.users if self.du.get((u, attr)) == val2}
                if matching_users:
                    users = matching_users
                    break
        
        if not resources:
            for attr in self.resource_attributes:
                matching_resources = {r for r in self.resources if self.dr.get((r, attr)) == val1}
                if matching_resources:
                    resources = matching_resources
                    break
        
        return users, resources, {operation}

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
        
        print(f"Enhanced merging: {initial_count - len(rules)} rules merged")

    def can_merge_rules(self, rule1: ABACRule, rule2: ABACRule) -> bool:
        """Check if rules can be merged."""
        return (rule1.operations == rule2.operations and 
                rule1.constraints == rule2.constraints)

    def merge_two_rules(self, rule1: ABACRule, rule2: ABACRule) -> ABACRule:
        """Merge two compatible rules."""
        merged_user_expr = {}
        for attr in set(rule1.user_expr.keys()) | set(rule2.user_expr.keys()):
            vals = rule1.user_expr.get(attr, set()) | rule2.user_expr.get(attr, set())
            if vals:
                merged_user_expr[attr] = vals
        
        merged_resource_expr = {}
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
            
            # Skip rules with too few attributes (side-normalized)
            u_space = max(len(self.user_attributes), 1)
            r_space = max(len(self.resource_attributes), 1)
            u_ratio = len(rule.user_expr) / u_space
            r_ratio = len(rule.resource_expr) / r_space
            avg_expr_ratio = 0.5 * (u_ratio + r_ratio)
            if avg_expr_ratio < 0.05:  # Less than 5% average expression
                continue
            
            filtered_rules.append(rule)
        
        rules.clear()
        rules.extend(filtered_rules)
        print(f"Enhanced simplification: {initial_count - len(rules)} rules removed")

    def compute_rule_coverage_bucketed(self, rule):
        """Dynamic bucketed coverage computation."""
        # Check if rule fixes specific resource attributes
        resource_attrs = list(self.resource_attributes.keys())
        resources = self.resources
        
        if len(resource_attrs) >= 2:
            attr1, attr2 = resource_attrs[0], resource_attrs[1]
            tset = rule.resource_expr.get(attr1)
            sset = rule.resource_expr.get(attr2)
            if tset and sset and len(tset) == 1 and len(sset) == 1:
                t = next(iter(tset))
                s = next(iter(sset))
                resources = [r for r in self.resources 
                           if self.dr.get((r, attr1)) == t and self.dr.get((r, attr2)) == s]
        elif len(resource_attrs) == 1:
            attr1 = resource_attrs[0]
            tset = rule.resource_expr.get(attr1)
            if tset and len(tset) == 1:
                t = next(iter(tset))
                resources = [r for r in self.resources if self.dr.get((r, attr1)) == t]
        
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

        # 2) Bucket-first seeding: pick best one per resource attribute bucket
        resource_attrs = list(self.resource_attributes.keys())
        if len(resource_attrs) >= 2:
            attr1, attr2 = resource_attrs[0], resource_attrs[1]
            bucket_key = lambda r: (
                tuple(sorted(r.resource_expr.get(attr1, []))),
                tuple(sorted(r.resource_expr.get(attr2, []))),
                tuple(sorted(r.operations)),
            )
        elif len(resource_attrs) == 1:
            attr1 = resource_attrs[0]
            bucket_key = lambda r: (
                tuple(sorted(r.resource_expr.get(attr1, []))),
                tuple(sorted(r.operations)),
            )
        else:
            bucket_key = lambda r: (
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
            print(f"Adding fallback rules for {len(remaining_permissions)} remaining permissions")
            for rule, quality, coverage_size in rule_scores:
                if rule in selected_rules:
                    continue
                if add_rule_if_new_coverage(rule, min_quality=0.02):
                    if len(selected_rules) >= 40:
                        break

        print(f"Enhanced selection: {len(selected_rules)} rules selected")
        if len(self.UP) > 0:
            print(f"Coverage: {len(covered_permissions)}/{len(self.UP)} permissions ({len(covered_permissions)/len(self.UP)*100:.1f}%)")
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
              Example: {"alice": {"department": "Finance"}, ...}
            - For 'log': A list of dictionaries, each representing a log entry.
              Example: [{'user_name': 'alice', 'object_name': 'budget_2024', ...}, ...]
    """
    if file_type in ['user', 'resource']:
        result: Dict[str, Dict[str, str]] = {}
    elif file_type == 'log':
        result: List[Dict[str, str]] = []
    else:
        raise ValueError(f"Unsupported file_type: {file_type}. Expected 'user', 'resource', or 'log'.")

    for line_num, line in enumerate(file_content.splitlines(), 1):
        stripped_line = line.strip()

        # Ignore comments and blank lines
        if not stripped_line or stripped_line.startswith('#'):
            continue

        # Handle '<' and '>' characters
        if stripped_line.startswith('<') and stripped_line.endswith('>'):
            clean_line = stripped_line[1:-1].strip()
        else:
            print(f"Warning: Line {line_num} in '{file_type}' file is malformed (missing '<' or '>'): '{stripped_line}'. Skipping.")
            continue

        if not clean_line:
            continue # Line might become empty after stripping < >

        tokens = clean_line.split()

        if not tokens:
            print(f"Warning: Line {line_num} in '{file_type}' file is empty after cleaning. Skipping.")
            continue

        try:
            if file_type in ['user', 'resource']:
                # Format: <name key1:value1 key2:value2 ...>
                entity_name = tokens[0]
                attributes: Dict[str, str] = {}
                for token in tokens[1:]:
                    if ':' in token:
                        key, value = token.split(':', 1)
                        attributes[key.strip()] = value.strip()
                    else:
                        print(f"Warning: Line {line_num} in '{file_type}' file contains malformed attribute '{token}'. Skipping attribute.")
                result[entity_name] = attributes
            elif file_type == 'log':
                # Format: <user resource op time decision>
                if len(tokens) == 5:
                    log_entry = {
                        'user_name': tokens[0],
                        'object_name': tokens[1],
                        'action': tokens[2],
                        'time': tokens[3],
                        'decision': tokens[4]
                    }
                    result.append(log_entry)
                else:
                    print(f"Warning: Line {line_num} in '{file_type}' file has incorrect number of fields ({len(tokens)} instead of 5): '{clean_line}'. Skipping.")
        except Exception as e:
            print(f"Warning: Error parsing line {line_num} in '{file_type}' file: '{clean_line}'. Error: {e}. Skipping.")

    return result

def read_file_content(filename: str) -> str:
    """Reads the entire content of a file and handles potential errors."""
    try:
        with open(filename, 'r') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found. Please ensure it is in the correct directory.")
        return "" # Return empty string if file is not found


def main():
    """Main function to orchestrate the ABAC policy mining process."""
    # 1. Define fixed filenames
    users_filename = "abac_user.txt"
    resources_filename = "abac_object.txt"
    logs_filename = "abac_logs.txt"

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

    print(f"Parsing complete: {len(users_data)} users, {len(resources_data)} resources, and {len(logs)} log entries processed.")

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
    print(f"\n--- Generated {len(final_rules)} ABAC Rules ---")
    if not final_rules:
        print("No robust rules were generated based on the provided logs that passed quality checks.")
    else:
        for i, rule in enumerate(final_rules, 1):
            print(f"\nRule {i}: {rule}")
            print(f"  WSC (Complexity): {rule.wsc()}")
            
            coverage_percentage = 0.0
            if miner.UP:
                # Calculate true positives covered by this specific rule
                rule_coverage_up = miner.compute_rule_coverage(rule) & miner.UP
                coverage_percentage = (len(rule_coverage_up) / len(miner.UP)) * 100
            print(f"  Approx. True Positive Coverage: {coverage_percentage:.2f}% of total allowed permissions.")

if __name__ == "__main__":
    start = time.time()
    main()
    end = time.time()
    print(f"Elapsed time: {end - start:.4f} seconds")
