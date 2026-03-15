import json
import networkx as nx
import argparse
from pdf_reporter import export_full_pdf_report

class AttackPathGraph:
    def __init__(self):
        # Initialize the Directed Graph
        self.G = nx.DiGraph()

    def load_from_json(self, filepath):
        """Ingests the cluster-graph.json and builds the NetworkX graph."""
        try:
            with open(filepath, 'r') as file:
                data = json.load(file)
                
            # 1. Load Nodes
            for node in data.get("nodes", []):
                node_id = node.pop("id") # Extract ID to use as the NetworkX node key
                self.G.add_node(node_id, **node) # Load the rest as attributes
                
            # 2. Load Edges
            for edge in data.get("edges", []):
                source = edge.pop("source")
                target = edge.pop("target")
                self.G.add_edge(source, target, **edge)
                
            print(f"[*] Graph loaded successfully: {self.G.number_of_nodes()} Nodes, {self.G.number_of_edges()} Edges.")
            return True
        except Exception as e:
            print(f"[!] Error loading graph: {e}")
            return False

    def get_entry_points(self):
        """Dynamically finds nodes tagged as public entry points."""
        return [n for n, attr in self.G.nodes(data=True) if attr.get("meta", {}).get("entry_point") == True]

    def get_crown_jewels(self):
        """Dynamically finds nodes tagged as crown jewels."""
        return [n for n, attr in self.G.nodes(data=True) if attr.get("meta", {}).get("crown_jewel") == True]

    # ==========================================
    # CORE ALGORITHMS
    # ==========================================

    def get_shortest_path(self, source_node, target_node):
        """Algorithm 2: Shortest Path via Dijkstra's algorithm."""
        if source_node not in self.G or target_node not in self.G:
            return {"error": "Source or target not found."}
        try:
            attack_path = nx.dijkstra_path(self.G, source=source_node, target=target_node, weight='weight')
            total_risk = sum(self.G[u][v].get('risk_score', 0) for u, v in zip(attack_path[:-1], attack_path[1:]))
            return {
                "path": attack_path,
                "total_hops": len(attack_path) - 1,
                "total_risk_score": round(total_risk, 2)
            }
        except nx.NetworkXNoPath:
            return {"error": "No path exists."}

    def get_blast_radius(self, source_node, max_hops=3):
        """Algorithm 1: Blast Radius via BFS."""
        if source_node not in self.G:
            return {"error": "Source not found."}
        reachable = nx.single_source_shortest_path_length(self.G, source=source_node, cutoff=max_hops)
        danger_zone = [n for n in reachable.keys() if n != source_node]
        return {
            "total_reachable": len(danger_zone),
            "max_hops_checked": max_hops
        }

    def detect_cycles(self):
        """Algorithm 3: Circular Permission Detection via DFS."""
        cycles = list(nx.simple_cycles(self.G))
        formatted_cycles = [c for c in cycles if len(c) > 1]
        return formatted_cycles

    # Update this method inside the AttackPathGraph class in graph_builder.py

    def identify_critical_node(self, source, target):
        """Identifies the bottleneck node and provides dynamic remediation."""
        try:
            # Get the path we are analyzing
            path_res = self.get_shortest_path(source, target)
            if "error" in path_res:
                return {"message": "No path to analyze."}

            path = path_res["path"]
            
            # Usually, the 'bottleneck' is the node right before the target 
            # or the ServiceAccount that bridges the Pod to the Cluster
            # For this logic, we'll analyze the 'highest risk' edge in the path
            best_advice = "Generic: Review RBAC permissions."
            bottleneck_node = None
            max_edge_risk = -1

            for i in range(len(path) - 1):
                u, v = path[i], path[i+1]
                edge_data = self.G[u][v]
                rel = edge_data.get('relation', 'default-remediation')
                
                # Check our map for specific advice
                if edge_data.get('risk_score', 0) > max_edge_risk:
                    max_edge_risk = edge_data.get('risk_score')
                    bottleneck_node = u
                    from config import REMEDIATION_MAP
                    best_advice = REMEDIATION_MAP.get(rel, REMEDIATION_MAP["default-remediation"])

            return {
                "node": bottleneck_node,
                "recommendation": best_advice
            }
        except Exception as e:
            return {"message": f"Remediation analysis failed: {str(e)}"}

# ==========================================
# CLI REPORT GENERATOR
# ==========================================

import networkx as nx

def generate_report(graph):
    entry_points = graph.get_entry_points()
    crown_jewels = graph.get_crown_jewels()

    if not crown_jewels:
        print("[!] No crown jewels or critical vulnerabilities found in the cluster.")
        return

    all_detected_paths = []
    
    def find_all_paths(sources):
        paths_found = []
        for source in sources:
            for target in crown_jewels:
                try:
                    # Cutoff 6 is usually enough for K8s Goat, increase to 8 if needed
                    paths = nx.all_simple_paths(graph.G, source=source, target=target, cutoff=8)
                    for p in paths:
                        risk = sum(graph.G[u][v].get('risk_score', 0) for u, v in zip(p[:-1], p[1:]))
                        paths_found.append({
                            "source": source,
                            "target": target,
                            "path": p,
                            "total_risk_score": risk, # FIX: Renamed from total_risk
                            "total_hops": len(p) - 1
                        })
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
        return paths_found

    # ==========================================
    # PHASE 1 & 2: Search ALL Entry Points
    # ==========================================
    # Search from Internet
    all_detected_paths.extend(find_all_paths(entry_points))
    
    # ALWAYS check internal Pods (Assumed Breach) to find lateral movement
    print("[*] Performing 'Assumed Breach' scan for internal lateral movement...")
    all_pods = [n for n, d in graph.G.nodes(data=True) if d.get('type') == 'Pod']
    all_detected_paths.extend(find_all_paths(all_pods))

    # Remove duplicate paths (in case a Pod is reached both by Internet and internal scan)
    unique_paths = { tuple(p['path']): p for p in all_detected_paths }.values()
    all_detected_paths = sorted(unique_paths, key=lambda x: x['total_risk_score'], reverse=True)

    print("\n" + "="*60)
    print("KILL CHAIN LIST".center(60))
    print("="*60 + "\n")

    if not all_detected_paths:
        print("✅ SECURE: No paths detected from any entry point or internal Pod to any crown jewel.")
        critical_res = {"message": "No paths to break."}
        worst_path = None
    else:
        # We still identify the 'worst_path' for the Dashboard and Blast Radius
        worst_path = all_detected_paths[0]
        
        # Display the Top 5 Paths in the CLI
        for idx, p_data in enumerate(all_detected_paths[:5]):
            # FIX: Use total_risk_score to match the find_all_paths function
            score = p_data.get('total_risk_score', 0)
            severity = "CRITICAL" if score >= 15 else "HIGH" if score >= 8 else "MEDIUM"
            
            print(f"[Path #{idx+1}] {severity} (Risk: {score})")
            print(f"  Entry: {p_data['source']}")
            
            path = p_data['path']
            for u, v in zip(path[:-1], path[1:]):
                edge_data = graph.G[u][v]
                print(f"    → [{edge_data.get('relation')}] {v}")
            print("-" * 30)
    # ==========================================
    # ANALYTICS & REMEDIATION
    # ==========================================
    
    # Blast Radius (Using the source of the worst path)
    blast_source = worst_path["source"] if worst_path else (entry_points[0] if entry_points else "Internet")
    blast = graph.get_blast_radius(blast_source)
    if "error" not in blast:
        print(f"\n✓ Blast Radius of {blast_source}: {blast['total_reachable']} resources within {blast['max_hops_checked']} hops")

    # Cycles
    cycles = graph.detect_cycles()
    if cycles:
        print(f"✓ Cycles Detected: {len(cycles)}")
    else:
        print("✓ Cycles Detected: 0")

    # Dynamic Remediation for Top Paths
    print("\n" + "="*60)
    print("TOP REMEDIATIONS".center(60))
    print("="*60)
    
    if all_detected_paths:
        seen_advice = set()
        # Analyze the top 3 unique paths for the most impactful remediation
        for p_data in all_detected_paths[:3]:
            res = graph.identify_critical_node(p_data['source'], p_data['target'])
            advice = res.get('recommendation')
            if advice and advice not in seen_advice:
                print(f"• [For {p_data['target']}]: {advice}")
                seen_advice.add(advice)
        # Store for exports
        critical_res = {"recommendation": list(seen_advice)[0] if seen_advice else "General Hardening Required"}
    else:
        print("No critical nodes to remediate.")
        critical_res = {"message": "Cluster is currently secure."}

    print("="*60 + "\n")

    # ==========================================
    # EXPORTS (Dashboard & PDF)
    # ==========================================
    
    # 1. CLI UI (Still uses worst_path for the primary visual)
    from cli_ui_components import display_rich_dashboard
    display_rich_dashboard(worst_path, blast, cycles, critical_res, graph)

    # 2. PDF Report (Using the new full audit exporter)
    from pdf_reporter import export_full_pdf_report
    if all_detected_paths:
        # Pass the graph reference into the dict for PDF parsing
        for p in all_detected_paths: p['graph_ref'] = graph
        export_full_pdf_report(all_detected_paths, graph)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kubernetes Attack Path Visualizer - Graph Engine")
    parser.add_argument("-i", "--input", default="cluster-graph.json", help="Path to the cluster-graph.json file")
    args = parser.parse_args()

    ag = AttackPathGraph()
    if ag.load_from_json(args.input):
        generate_report(ag)