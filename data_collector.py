import subprocess
import json
from risk_matrix import evaluate_permission

# Mock CVE Database for Bonus Points
MOCK_CVE_DB = {
    "nginx:1.14": {"cve": "CVE-2021-23017", "score": 9.8},
    "tomcat:8.5": {"cve": "CVE-2020-1938", "score": 9.8}
}

class K8sDataCollector:
    def __init__(self):
        self.nodes = []
        self.edges = []
        self.raw_data = {}
        
        # Caches to help resolve targets later
        self.known_secrets = {} 
        self.known_pods = []

    def run_kubectl(self, resource):
        """Executes kubectl and returns the JSON output."""
        print(f"Fetching {resource}...")
        try:
            result = subprocess.run(
                ["kubectl", "get", resource, "-A", "-o", "json"], 
                capture_output=True, text=True, check=True
            )
            return json.loads(result.stdout).get("items", [])
        except subprocess.CalledProcessError as e:
            print(f"Warning: Failed to fetch {resource}. Is the cluster running?")
            return []

    def fetch_all_data(self):
        """Pulls all necessary resources from the live cluster."""
        resources = ["pods", "serviceaccounts", "roles", "clusterroles", 
                     "rolebindings", "clusterrolebindings", "secrets"]
        for res in resources:
            self.raw_data[res] = self.run_kubectl(res)

    def parse_pods(self):
        """Extracts Pod nodes and draws edges to their ServiceAccounts."""
        for pod in self.raw_data.get("pods", []):
            meta = pod.get("metadata", {})
            spec = pod.get("spec", {})
            
            pod_id = f"Pod-{meta.get('namespace')}-{meta.get('name')}"
            self.known_pods.append(pod_id)
            
            # Base Node setup
            node = {
                "id": pod_id,
                "type": "Pod",
                "namespace": meta.get("namespace"),
                "labels": meta.get("labels", {}),
                "risk_score": 1.0
            }
            
            # Check Mock CVEs
            for container in spec.get("containers", []):
                image = container.get("image")
                if image in MOCK_CVE_DB:
                    node["cve"] = MOCK_CVE_DB[image]["cve"]
                    node["risk_score"] = MOCK_CVE_DB[image]["score"]
            
            self.nodes.append(node)

            # Edge: Pod -> ServiceAccount
            sa_name = spec.get("serviceAccountName", "default")
            sa_id = f"ServiceAccount-{meta.get('namespace')}-{sa_name}"
            
            self.edges.append({
                "source": pod_id,
                "target": sa_id,
                "relation": "uses_sa",
                "weight": node["risk_score"] # Vulnerable pods create riskier edges
            })

    def parse_service_accounts(self):
        """Extracts ServiceAccount nodes."""
        for sa in self.raw_data.get("serviceaccounts", []):
            meta = sa.get("metadata", {})
            sa_id = f"ServiceAccount-{meta.get('namespace')}-{meta.get('name')}"
            
            self.nodes.append({
                "id": sa_id,
                "type": "ServiceAccount",
                "namespace": meta.get("namespace"),
                "risk_score": 0.0
            })

    def parse_bindings(self):
        """Extracts bindings and draws edges from SAs to Roles/ClusterRoles."""
        # 1. Namespace-scoped RoleBindings
        for rb in self.raw_data.get("rolebindings", []):
            meta = rb.get("metadata", {})
            namespace = meta.get("namespace", "default")
            role_ref = rb.get("roleRef", {})
            
            target_role_id = f"{role_ref.get('kind')}-{namespace}-{role_ref.get('name')}"
            if role_ref.get("kind") == "ClusterRole":
                target_role_id = f"ClusterRole-{role_ref.get('name')}"

            for sub in rb.get("subjects", []):
                if sub.get("kind") == "ServiceAccount":
                    sa_ns = sub.get("namespace", namespace)
                    source_sa_id = f"ServiceAccount-{sa_ns}-{sub.get('name')}"
                    
                    self.edges.append({
                        "source": source_sa_id,
                        "target": target_role_id,
                        "relation": "bound_to",
                        "weight": 1.0
                    })

        # 2. ClusterRoleBindings
        for crb in self.raw_data.get("clusterrolebindings", []):
            role_ref = crb.get("roleRef", {})
            target_role_id = f"ClusterRole-{role_ref.get('name')}"
            
            for sub in crb.get("subjects", []):
                if sub.get("kind") == "ServiceAccount":
                    sa_ns = sub.get("namespace", "default")
                    source_sa_id = f"ServiceAccount-{sa_ns}-{sub.get('name')}"
                    
                    self.edges.append({
                        "source": source_sa_id,
                        "target": target_role_id,
                        "relation": "cluster_bound_to",
                        "weight": 2.0 # Cluster bounds are inherently riskier
                    })

    def parse_roles_and_rules(self):
        """Extracts Role nodes and evaluates their rules using the Risk Matrix."""
        all_roles = self.raw_data.get("roles", []) + self.raw_data.get("clusterroles", [])
        
        for role in all_roles:
            meta = role.get("metadata", {})
            kind = role.get("kind") # 'Role' or 'ClusterRole'
            namespace = meta.get("namespace", "cluster-wide")
            
            if kind == "ClusterRole":
                role_id = f"ClusterRole-{meta.get('name')}"
            else:
                role_id = f"Role-{namespace}-{meta.get('name')}"
                
            self.nodes.append({
                "id": role_id,
                "type": kind,
                "namespace": namespace,
                "risk_score": 0.0
            })
            
            # Evaluate Rules for edges
            for rule in role.get("rules", []):
                resources = rule.get("resources", [])
                verbs = rule.get("verbs", [])
                
                # Use our external risk matrix module!
                risk_data = evaluate_permission(resources, verbs)
                
                if risk_data:
                    self.edges.append({
                        "source": role_id,
                        "target": f"Target-Placeholder-{resources[0]}", # We will fix this next!
                        "relation": risk_data["desc"],
                        "weight": risk_data["difficulty_weight"],
                        "risk_score": risk_data["risk_score"]
                    })

    def export_to_json(self, filename="cluster-graph.json"):
        """Saves the complete graph schema to a file."""
        output = {"nodes": self.nodes, "edges": self.edges}
        with open(filename, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\n✅ Success! Exported {len(self.nodes)} nodes and {len(self.edges)} edges to {filename}")

# ==========================================
# Execution
# ==========================================
if __name__ == "__main__":
    collector = K8sDataCollector()
    collector.fetch_all_data()
    
    collector.parse_pods()
    collector.parse_service_accounts()
    collector.parse_bindings()
    collector.parse_roles_and_rules()
    
    collector.export_to_json()