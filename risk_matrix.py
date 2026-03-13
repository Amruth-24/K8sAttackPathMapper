# risk_matrix.py

"""
Kubernetes RBAC Risk Matrix
Maps (resource, verb) combinations to exploitability metrics.

- risk_score: Used for the final Kill Chain Report severity (1-10).
- difficulty_weight: Used as the edge weight for Dijkstra's algorithm (Lower = easier/faster to exploit).
"""

_MATRIX = {
    # =========================================================================
    # 1. TOTAL CLUSTER TAKEOVER (God Mode)
    # =========================================================================
    ("*", "*"): {
        "risk_score": 10.0, 
        "difficulty_weight": 1.0, 
        "desc": "Full Cluster Admin (Wildcard)"
    },
    ("nodes", "*"): {
        "risk_score": 9.5, 
        "difficulty_weight": 1.5, 
        "desc": "Full Node Access"
    },
    ("nodes/proxy", "create"): {
        "risk_score": 9.5, 
        "difficulty_weight": 1.5, 
        "desc": "Kubelet API Takeover"
    },

    # =========================================================================
    # 2. RBAC PRIVILEGE ESCALATION [cite: 126, 128, 301]
    # =========================================================================
    ("clusterroles", "escalate"): {
        "risk_score": 9.0, 
        "difficulty_weight": 2.0, 
        "desc": "ClusterRole Escalation"
    },
    ("clusterroles", "bind"): {
        "risk_score": 9.0, 
        "difficulty_weight": 2.0, 
        "desc": "ClusterRole Binding"
    },
    ("roles", "escalate"): {
        "risk_score": 8.5, 
        "difficulty_weight": 2.5, 
        "desc": "Role Escalation"
    },
    ("roles", "bind"): {
        "risk_score": 8.5, 
        "difficulty_weight": 2.5, 
        "desc": "Role Binding"
    },
    ("rolebindings", "create"): {
        "risk_score": 8.0, 
        "difficulty_weight": 3.0, 
        "desc": "Create RoleBindings"
    },
    ("rolebindings", "update"): {
        "risk_score": 8.0, 
        "difficulty_weight": 3.0, 
        "desc": "Modify RoleBindings"
    },

    # =========================================================================
    # 3. IDENTITY IMPERSONATION [cite: 128, 301]
    # =========================================================================
    ("users", "impersonate"): {
        "risk_score": 8.5, 
        "difficulty_weight": 2.0, 
        "desc": "User Impersonation"
    },
    ("groups", "impersonate"): {
        "risk_score": 8.5, 
        "difficulty_weight": 2.0, 
        "desc": "Group Impersonation"
    },
    ("serviceaccounts", "impersonate"): {
        "risk_score": 8.0, 
        "difficulty_weight": 2.5, 
        "desc": "ServiceAccount Impersonation"
    },
    ("serviceaccounts/token", "create"): {
        "risk_score": 8.5, 
        "difficulty_weight": 2.0, 
        "desc": "Mint Arbitrary SA Tokens"
    },

    # =========================================================================
    # 4. WORKLOAD COMPROMISE & EXECUTION
    # =========================================================================
    ("pods/exec", "create"): {
        "risk_score": 8.5, 
        "difficulty_weight": 2.0, 
        "desc": "Execute Code in Pods"
    },
    ("pods/attach", "create"): {
        "risk_score": 8.0, 
        "difficulty_weight": 2.5, 
        "desc": "Attach to Pods"
    },
    ("pods/portforward", "create"): {
        "risk_score": 7.0, 
        "difficulty_weight": 3.5, 
        "desc": "Port Forwarding to Pods"
    },
    ("daemonsets", "create"): {
        "risk_score": 8.0, 
        "difficulty_weight": 3.0, 
        "desc": "Create DaemonSets (Potential Node Compromise)"
    },
    ("deployments", "create"): {
        "risk_score": 7.5, 
        "difficulty_weight": 3.5, 
        "desc": "Create Deployments"
    },
    ("pods", "create"): {
        "risk_score": 7.0, 
        "difficulty_weight": 4.0, 
        "desc": "Create Pods"
    },

    # =========================================================================
    # 5. CROWN JEWEL ACCESS (Data Exfiltration) [cite: 128, 300]
    # =========================================================================
    ("secrets", "*"): {
        "risk_score": 8.5, 
        "difficulty_weight": 2.0, 
        "desc": "Full Control of Secrets"
    },
    ("secrets", "get"): {
        "risk_score": 8.0, 
        "difficulty_weight": 2.5, 
        "desc": "Read Specific Secrets"
    },
    ("secrets", "list"): {
        "risk_score": 7.5, 
        "difficulty_weight": 3.0, 
        "desc": "List All Secrets"
    },

    # =========================================================================
    # 6. ADVANCED / STEALTH VECTORS
    # =========================================================================
    ("mutatingwebhookconfigurations", "create"): {
        "risk_score": 8.0, 
        "difficulty_weight": 3.0, 
        "desc": "Webhook Injection (Sidecar attacks)"
    },
    ("mutatingwebhookconfigurations", "update"): {
        "risk_score": 8.0, 
        "difficulty_weight": 3.0, 
        "desc": "Webhook Modification"
    },
    ("certificatesigningrequests/approval", "update"): {
        "risk_score": 8.5, 
        "difficulty_weight": 2.5, 
        "desc": "Approve Malicious Certificates"
    }
}

def evaluate_permission(resources_list, verbs_list):
    """
    Evaluates lists of resources and verbs against the risk matrix.
    Returns the highest risk matched, or None if the action is considered safe.
    """
    highest_risk = None
    min_difficulty = float('inf')
    best_match = None

    for res in resources_list:
        for verb in verbs_list:
            # Check exact match
            match = _MATRIX.get((res, verb))
            
            # Check if verb is covered by a resource wildcard
            if not match:
                match = _MATRIX.get((res, "*"))
                
            # Check if resource is covered by a global wildcard
            if not match:
                match = _MATRIX.get(("*", verb))
                
            # Global wildcard
            if not match:
                match = _MATRIX.get(("*", "*"))

            if match:
                # We want to capture the easiest, highest-risk path available in these rules
                if match["difficulty_weight"] < min_difficulty:
                    min_difficulty = match["difficulty_weight"]
                    highest_risk = match["risk_score"]
                    best_match = match

    return best_match