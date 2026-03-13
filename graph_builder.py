import networkx as nx

class AttackPathGraph:
    def __init__(self):
        self.G = nx.DiGraph()

    def load_nodes(self, nodes_data):
        self.G.add_nodes_from(nodes_data)

    def load_edges(self, edges_data):
        self.G.add_edges_from(edges_data)

    def get_blast_radius(self, source_node, max_hops=3):
        """
        Algorithm 1: Blast Radius Detection (BFS)
        Returns a dictionary of nodes reachable within 'max_hops' 
        and their exact distance from the source.
        """
        if source_node not in self.G:
            return f"Error: Source node '{source_node}' not found in graph."

        # NetworkX's BFS implementation with a depth limit
        reachable_nodes = nx.single_source_shortest_path_length(
            self.G, 
            source=source_node, 
            cutoff=max_hops
        )
        
        # We can format this into the "Danger Zone" output
        danger_zone = list(reachable_nodes.keys())
        
        # Remove the source node itself from the danger zone list if desired
        if source_node in danger_zone:
            danger_zone.remove(source_node)
            
        return {
            "source": source_node,
            "max_hops_checked": max_hops,
            "total_reachable": len(danger_zone),
            "danger_zone_nodes": danger_zone,
            "distances": reachable_nodes # Keeps the exact hop count for each node
        }

    def get_shortest_path_to_crown_jewel(self, source_node, target_node):
        """
        Algorithm 2: Shortest Path to Crown Jewels (Dijkstra's Algorithm)
        Calculates the easiest route based on edge weights (exploitability scores).
        """
        if source_node not in self.G or target_node not in self.G:
            return {"error": "Source or target node not found in the graph."}

        try:
            # NetworkX's built-in Dijkstra's algorithm
            # The 'weight' parameter tells it to use our exploitability scores
            attack_path = nx.dijkstra_path(
                self.G, 
                source=source_node, 
                target=target_node, 
                weight='weight' 
            )
            
            # Calculate the total risk score (sum of weights along the path)
            total_risk_score = nx.dijkstra_path_length(
                self.G, 
                source=source_node, 
                target=target_node, 
                weight='weight'
            )
            
            # Total hops is the number of edges, which is nodes - 1
            total_hops = len(attack_path) - 1
            
            return {
                "source": source_node,
                "target": target_node,
                "path": attack_path,
                "total_hops": total_hops,
                "total_risk_score": round(total_risk_score, 2) # Rounding for cleaner output
            }
            
        except nx.NetworkXNoPath:
            # Crucial for K8s environments where many pods are properly isolated
            return {"error": f"Safe! No path exists between '{source_node}' and '{target_node}'."}

    def detect_circular_permissions(self):
        """
        Algorithm 3: Circular Permission Detection (DFS)
        Detects misconfigured mutual grants (cycles) in the cluster graph.
        """
        try:
            # nx.simple_cycles uses a DFS-based algorithm to find all cycles
            cycles = list(nx.simple_cycles(self.G))
            
            formatted_cycles = []
            for cycle in cycles:
                # We usually care about cycles involving 2 or more nodes 
                # (e.g., mutual grants between two services)
                if len(cycle) > 1:
                    # Format for the required output: A -> B -> A
                    cycle_str = " -> ".join(cycle) + f" -> {cycle[0]}"
                    formatted_cycles.append({
                        "nodes": cycle,
                        "length": len(cycle),
                        "description": cycle_str
                    })
                    
            return {
                "total_cycles": len(formatted_cycles),
                "cycles": formatted_cycles
            }
            
        except nx.NetworkXNotImplemented:
            return {"error": "Cycle detection requires a directed graph."}
    

    def identify_critical_node(self, source_node, target_node):
        """
        Task 4: Critical Node Identification
        Finds the single node whose removal breaks the most attack paths.
        """
        if source_node not in self.G or target_node not in self.G:
            return {"error": "Source or target node not found."}

        # Find all valid attack paths from the entry point to the crown jewel
        all_paths = list(nx.all_simple_paths(self.G, source_node, target_node))
        baseline_path_count = len(all_paths)

        if baseline_path_count == 0:
            return {"message": "Safe! No paths exist from this source to the target."}

        max_reduction = 0
        critical_node = None

        # Evaluate each node in the graph
        for node in self.G.nodes():
            # We don't remove the source (attacker) or the target (crown jewel) itself
            if node == source_node or node == target_node:
                continue
                
            # A surviving path is one that does NOT contain the removed node
            surviving_paths = [path for path in all_paths if node not in path]
            new_path_count = len(surviving_paths)
            
            # Calculate how many paths were broken by removing this node
            reduction = baseline_path_count - new_path_count
            
            # Track the node that causes the biggest reduction
            if reduction > max_reduction:
                max_reduction = reduction
                critical_node = node

        # If removing a node doesn't break any paths (or if no intermediate nodes exist)
        if critical_node is None:
            return {"message": "No single intermediate node breaks the existing paths."}

        return {
            "critical_node": critical_node,
            "baseline_paths": baseline_path_count,
            "paths_eliminated": max_reduction,
            "recommendation_string": f"Recommendation: Remove '{critical_node}' to eliminate {max_reduction} of {baseline_path_count} attack paths."
        }

# ==========================================
# Dummy Data & Execution
# ==========================================



# if __name__ == "__main__":
#     dummy_nodes = [
#         ("pod-public-api", {"type": "Pod"}),
#         ("sa-webapp", {"type": "ServiceAccount"}),
#         ("role-secret-reader", {"type": "Role"}),
#         ("secret-db-creds", {"type": "Secret"}),
#         ("production-db", {"type": "Database"}),
#         ("service-A", {"type": "Service"}), 
#         ("service-B", {"type": "Service"})
#     ]

#     dummy_edges = [
#         ("pod-public-api", "sa-webapp", {"weight": 8.1}),
#         ("sa-webapp", "role-secret-reader", {"weight": 1.0}),
#         ("role-secret-reader", "secret-db-creds", {"weight": 5.0}),
#         ("secret-db-creds", "production-db", {"weight": 10.6}),
        
#         # Simulating the cycle (mutual admin grant)
#         ("service-A", "service-B", {"weight": 1.0}),
#         ("service-B", "service-A", {"weight": 1.0}),
        
#         # Connecting the cycle to the main path so it can be reached
#         ("role-secret-reader", "service-A", {"weight": 2.0}),
#         # Add an alternative path to the crown jewel in the dummy_edges list
#     ("sa-webapp", "role-db-admin", {"weight": 2.0}),
#     ("role-db-admin", "production-db", {"weight": 1.5}), 
#     ]

#     attack_graph = AttackPathGraph()
#     attack_graph.load_nodes(dummy_nodes)
#     attack_graph.load_edges(dummy_edges)
    
#     # Let's test the Blast Radius from our public API pod
#     print("--- Testing Algorithm 1: Blast Radius ---")
#     blast_results = attack_graph.get_blast_radius("pod-public-api", max_hops=3)
    
#     print(f"Source: {blast_results['source']}")
#     print(f"Blast Radius ({blast_results['max_hops_checked']} hops): {blast_results['total_reachable']} resources")
#     print(f"Danger Zone: {blast_results['danger_zone_nodes']}")
#     print(f"Exact Distances: {blast_results['distances']}")

    
#     # Testing Shortest Path

#     print("\n--- Testing Algorithm 2: Shortest Path (Dijkstra) ---")
#     dijkstra_results = attack_graph.get_shortest_path_to_crown_jewel("pod-public-api", "production-db")
    
#     if "error" in dijkstra_results:
#         print(dijkstra_results["error"])
#     else:
#         print(f"Targeting: {dijkstra_results['target']}")
#         print(f"Attack Path: {' -> '.join(dijkstra_results['path'])}")
#         print(f"Total Hops: {dijkstra_results['total_hops']} | Path Risk Score: {dijkstra_results['total_risk_score']}")

#     # print(attack_graph.G.edges(data=True))

#     print("\n--- Testing Algorithm 3: Circular Permission Detection (DFS) ---")
#     dfs_results = attack_graph.detect_circular_permissions()
    
#     print(f"Cycles Detected: {dfs_results['total_cycles']}")
#     for cycle in dfs_results['cycles']:
#         # This formats perfectly into the required Kill Chain Report string
#         print(f" - ({' <-> '.join(cycle['nodes'])} mutual grant loop)")

    
#     print("\n--- Testing Task 4: Critical Node Identification ---")
#     critical_node_results = attack_graph.identify_critical_node("pod-public-api", "production-db")
    
#     if "error" in critical_node_results:
#         print(critical_node_results["error"])
#     elif "message" in critical_node_results:
#         print(critical_node_results["message"])
#     else:
#         # This matches the exact requested output format 
#         print(critical_node_results["recommendation_string"])



if __name__ == "__main__":
    # 1. Dummy Nodes
    dummy_nodes = [
        ("pod-public-api", {"type": "Pod"}),
        ("sa-webapp", {"type": "ServiceAccount"}),
        ("role-secret-reader", {"type": "Role"}),
        ("secret-db-creds", {"type": "Secret"}),
        ("production-db", {"type": "Database"}),
        ("role-db-admin", {"type": "Role"}),
        ("service-A", {"type": "Service"}), 
        ("service-B", {"type": "Service"})
    ]

    # 2. Dummy Edges (Includes main path, an alternate path for the critical node, and a cycle)
    dummy_edges = [
        # Path 1
        ("pod-public-api", "sa-webapp", {"weight": 8.1}),
        ("sa-webapp", "role-secret-reader", {"weight": 1.0}),
        ("role-secret-reader", "secret-db-creds", {"weight": 5.0}),
        ("secret-db-creds", "production-db", {"weight": 10.6}),
        # Path 2 (Alternative route to test Critical Node logic)
        ("sa-webapp", "role-db-admin", {"weight": 2.0}),
        ("role-db-admin", "production-db", {"weight": 8.5}),
        # Cycle
        ("service-A", "service-B", {"weight": 1.0}),
        ("service-B", "service-A", {"weight": 1.0}),
        ("role-secret-reader", "service-A", {"weight": 2.0}) 
    ]

    # Initialize and load
    attack_graph = AttackPathGraph()
    attack_graph.load_nodes(dummy_nodes)
    attack_graph.load_edges(dummy_edges)
    
    # Define targets
    entry_point = "pod-public-api"
    crown_jewel = "production-db"

    # Run the Core Algorithms
    shortest_path_res = attack_graph.get_shortest_path_to_crown_jewel(entry_point, crown_jewel)
    blast_radius_res = attack_graph.get_blast_radius(entry_point, max_hops=3)
    cycle_res = attack_graph.detect_circular_permissions()
    critical_node_res = attack_graph.identify_critical_node(entry_point, crown_jewel)

    # ==========================================
    # OUTPUT: KILL CHAIN REPORT
    # ==========================================
    print("\n" + "="*60)
    print("KILL CHAIN REPORT".center(60))
    print("="*60 + "\n")

    # 1. Attack Path Details
    if "error" not in shortest_path_res:
        print("⚠️ WARNING: Attack Path Detected")
        print(f"Resource '{entry_point}' can reach '{crown_jewel}' via:")
        
        path = shortest_path_res["path"]
        print(f"{path[0]}")
        for node in path[1:]:
            print(f"  → {node}")
            
        score = shortest_path_res["total_risk_score"]
        # Basic logic to assign severity string based on score
        severity = "CRITICAL" if score >= 20 else "HIGH" if score >= 10 else "MEDIUM"
        
        print(f"Total Hops: {shortest_path_res['total_hops']} | Path Risk Score: {score} ({severity})\n")
    else:
        print(f"✅ SECURE: No path detected from '{entry_point}' to '{crown_jewel}'.\n")

    # 2. Blast Radius
    if "error" not in blast_radius_res:
        print(f"✓ Blast Radius of {entry_point}: {blast_radius_res['total_reachable']} resources within {blast_radius_res['max_hops_checked']} hops")

    # 3. Cycles Detected
    if "error" not in cycle_res:
        cycle_count = cycle_res["total_cycles"]
        if cycle_count > 0:
            # Format: (Service-A <-> Service-B mutual admin grant)
            cycle_details = ", ".join([f"({' <-> '.join(c['nodes'])} mutual grant)" for c in cycle_res["cycles"]])
            print(f"✓ Cycles Detected: {cycle_count} {cycle_details}")
        else:
            print("✓ Cycles Detected: 0")

    # 4. Remediation / Critical Node
    print("\n" + "-"*60)
    if "recommendation_string" in critical_node_res:
        print(critical_node_res['recommendation_string'])
    elif "message" in critical_node_res:
        print(critical_node_res['message'])
        
    print("="*60 + "\n")