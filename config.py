# config.py

RESOURCE_TYPES = [
    "pods", "deployments", "daemonsets", "statefulsets", "serviceaccounts",
    "roles", "clusterroles", "rolebindings", "clusterrolebindings",
    "secrets", "configmaps", "services", "endpoints", "namespaces", "nodes",
    "ingresses" 
]

CROWN_JEWEL_KEYWORDS = ["db", "database", "password", "token", "credential", "secret", "admin"]

MOCK_CVE_LIST = [
    {"keyword": "nginx", "cve": "CVE-2024-1234", "cvss": 8.1, "desc": "Nginx off-by-one error"},
    {"keyword": "redis", "cve": "CVE-2023-41056", "cvss": 7.5, "desc": "Redis buffer overflow"},
    {"keyword": "tomcat", "cve": "CVE-2020-1938", "cvss": 9.8, "desc": "Ghostcat vulnerability"},
    {"keyword": "log4j", "cve": "CVE-2021-44228", "cvss": 10.0, "desc": "Log4Shell"}
]

# Risk Matrix Format: (resource, verb): {"risk_score": X, "difficulty_weight": Y, "desc": "Z"}
RISK_MATRIX = {
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
    Evaluates lists of resources and verbs against the RISK_MATRIX.
    Returns the dictionary of the most dangerous match, or None if safe.
    """
    min_difficulty = float('inf')
    best_match = None

    for res in resources_list:
        for verb in verbs_list:
            # Check exact match, resource wildcard, verb wildcard, or global wildcard
            match = RISK_MATRIX.get((res, verb)) or \
                    RISK_MATRIX.get((res, "*")) or \
                    RISK_MATRIX.get(("*", verb)) or \
                    RISK_MATRIX.get(("*", "*"))

            if match:
                # We want the easiest, highest-risk path available (lowest difficulty weight)
                if match["difficulty_weight"] < min_difficulty:
                    min_difficulty = match["difficulty_weight"]
                    best_match = match

    return best_match