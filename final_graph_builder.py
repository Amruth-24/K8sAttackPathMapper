import json
import networkx as nx
import argparse
from pdf_reporter import export_pdf_report

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

    def identify_critical_node(self, source_node, target_node):
        """Task 4: Finds the node that breaks the most paths."""
        try:
            all_paths = list(nx.all_simple_paths(self.G, source_node, target_node))
            baseline_count = len(all_paths)
            if baseline_count == 0:
                return {"message": "No paths to break."}

            max_reduction = 0
            critical_node = None

            for node in self.G.nodes():
                if node in (source_node, target_node):
                    continue
                surviving = [p for p in all_paths if node not in p]
                reduction = baseline_count - len(surviving)
                
                if reduction > max_reduction:
                    max_reduction = reduction
                    critical_node = node

            if critical_node:
                return {"recommendation": f"Recommendation: Remove '{critical_node}' to eliminate {max_reduction} of {baseline_count} attack paths."}
            return {"message": "No single node breaks the paths."}
        except nx.NetworkXNoPath:
             return {"message": "No paths to break."}

# ==========================================
# CLI REPORT GENERATOR
# ==========================================

def generate_report(graph):
    entry_points = graph.get_entry_points()
    crown_jewels = graph.get_crown_jewels()

    if not crown_jewels:
        print("[!] No crown jewels or critical vulnerabilities found in the cluster. Check Phase 1 JSON output.")
        return

    print("\n" + "="*60)
    print("KILL CHAIN REPORT".center(60))
    print("="*60 + "\n")

    worst_path = None
    max_risk = -1

    # ==========================================
    # PHASE 1: External Perimeter Attack
    # ==========================================
    for source in entry_points:
        for target in crown_jewels:
            path_res = graph.get_shortest_path(source, target)
            if "error" not in path_res:
                if path_res["total_risk_score"] > max_risk:
                    max_risk = path_res["total_risk_score"]
                    worst_path = path_res
                    worst_path["source"] = source
                    worst_path["target"] = target

    # ==========================================
    # PHASE 2: Assumed Breach (Internal Attack)
    # ==========================================
    if not worst_path:
        print("[*] INFO: Perimeter secure. Shifting to 'Assumed Breach' model (Internal Pod Compromise)...")
        # Grab every single Pod to test as an initial compromise point
        all_pods = [n for n, d in graph.G.nodes(data=True) if d.get('type') == 'Pod']
        
        for source in all_pods:
            for target in crown_jewels:
                path_res = graph.get_shortest_path(source, target)
                if "error" not in path_res:
                    if path_res["total_risk_score"] > max_risk:
                        max_risk = path_res["total_risk_score"]
                        worst_path = path_res
                        worst_path["source"] = source
                        worst_path["target"] = target

    # ==========================================
    # OUTPUT RESULTS
    # ==========================================
    if worst_path:
        print("⚠️ WARNING: Critical Attack Path Detected")
        print(f"Entry '{worst_path['source']}' can reach '{worst_path['target']}' via:")
        
        path = worst_path["path"]
        print(f"{path[0]}")
        for u, v in zip(path[:-1], path[1:]):
            edge_data = graph.G[u][v]
            cve_info = f" (CVE: {graph.G.nodes[u].get('cve')})" if graph.G.nodes[u].get('cve') else ""
            print(f"  → [{edge_data.get('relation')}] {v}{cve_info}")
        
        severity = "CRITICAL" if worst_path['total_risk_score'] >= 15 else "HIGH" if worst_path['total_risk_score'] >= 8 else "MEDIUM"
        print(f"\nTotal Hops: {worst_path['total_hops']} | Path Risk Score: {worst_path['total_risk_score']} ({severity})")
        
        # Run Critical Node analysis strictly on this worst path
        critical_res = graph.identify_critical_node(worst_path["source"], worst_path["target"])
    else:
        print("✅ SECURE: No paths detected from any entry point or internal Pod to any crown jewel.")
        critical_res = {"message": "No paths to break."}

    # Blast Radius (Using the source of the worst path, or the Internet)
    blast_source = worst_path["source"] if worst_path else entry_points[0]
    blast = graph.get_blast_radius(blast_source)
    if "error" not in blast:
        print(f"\n✓ Blast Radius of {blast_source}: {blast['total_reachable']} resources within {blast['max_hops_checked']} hops")

    # Cycles
    cycles = graph.detect_cycles()
    if cycles:
        cycle_strs = [f"({' <-> '.join(c)} mutual grant)" for c in cycles]
        print(f"✓ Cycles Detected: {len(cycles)} {', '.join(cycle_strs)}")
    else:
        print("✓ Cycles Detected: 0")

    # Critical Node
    print("\n" + "-"*60)
    print(critical_res.get('recommendation', critical_res.get('message')))
    print("="*60 + "\n")

    # CLI UI
    from cli_ui_components import display_rich_dashboard
    display_rich_dashboard(worst_path, blast, cycles, critical_res, graph)

    # Pass the graph reference into the worst_path dictionary so the PDF can read edge details
    if worst_path:
        worst_path['graph_ref'] = graph

    # Call the external module to generate the PDF
    export_pdf_report(worst_path, blast, cycles, critical_res)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kubernetes Attack Path Visualizer - Graph Engine")
    parser.add_argument("-i", "--input", default="cluster-graph.json", help="Path to the cluster-graph.json file")
    args = parser.parse_args()

    ag = AttackPathGraph()
    if ag.load_from_json(args.input):
        generate_report(ag)