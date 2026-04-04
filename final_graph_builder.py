import json
import networkx as nx
import argparse
from pdf_reporter import export_full_pdf_report


class AttackPathGraph:
    def __init__(self):
        self.G = nx.DiGraph()

    def load_from_json(self, filepath):
        """Ingests the cluster-graph.json and builds the NetworkX graph."""
        try:
            with open(filepath, 'r') as file:
                data = json.load(file)

            for node in data.get("nodes", []):
                node_copy = dict(node)          # FIX: don't mutate the original dict
                node_id = node_copy.pop("id")
                self.G.add_node(node_id, **node_copy)

            for edge in data.get("edges", []):
                edge_copy = dict(edge)          # FIX: don't mutate the original dict
                source = edge_copy.pop("source")
                target = edge_copy.pop("target")
                self.G.add_edge(source, target, **edge_copy)

            print(f"[*] Graph loaded: {self.G.number_of_nodes()} Nodes, {self.G.number_of_edges()} Edges.")
            return True
        except Exception as e:
            print(f"[!] Error loading graph: {e}")
            return False

    def get_entry_points(self):
        return [n for n, attr in self.G.nodes(data=True)
                if attr.get("meta", {}).get("entry_point") is True]

    def get_crown_jewels(self):
        return [n for n, attr in self.G.nodes(data=True)
                if attr.get("meta", {}).get("crown_jewel") is True]

    # ==========================================
    # CORE ALGORITHMS
    # ==========================================

    def get_shortest_path(self, source_node, target_node):
        """Algorithm 2: Shortest Path via Dijkstra's algorithm."""
        if source_node not in self.G or target_node not in self.G:
            return {"error": "Source or target not found."}
        try:
            attack_path = nx.dijkstra_path(
                self.G, source=source_node, target=target_node, weight='weight'
            )
            total_risk = sum(
                self.G[u][v].get('risk_score', 0)
                for u, v in zip(attack_path[:-1], attack_path[1:])
            )
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
        reachable = nx.single_source_shortest_path_length(
            self.G, source=source_node, cutoff=max_hops
        )
        danger_zone = [n for n in reachable if n != source_node]
        return {
            "total_reachable": len(danger_zone),
            "nodes": danger_zone,
            "max_hops_checked": max_hops
        }

    def detect_cycles(self):
        """Algorithm 3: Circular Permission Detection via DFS."""
        cycles = list(nx.simple_cycles(self.G))
        return [c for c in cycles if len(c) > 1]

    # ==========================================
    # TASK 4: CRITICAL NODE ANALYSIS (FIXED)
    # ==========================================

    def identify_critical_node(self, sources, crown_jewels, cutoff=8):
        """
        Task 4: For each candidate node, temporarily remove it from the graph,
        recount source-to-crown-jewel paths, and return the node whose removal
        eliminates the most attack paths.

        This is correct betweenness-style analysis on attack paths specifically,
        as required by the problem statement.
        """
        if not sources or not crown_jewels:
            return {"message": "No sources or crown jewels to analyse.", "recommendation": "Cluster appears secure."}

        # Step 1: Enumerate all baseline attack paths
        def _count_paths(graph):
            path_set = set()
            for src in sources:
                for tgt in crown_jewels:
                    if src not in graph or tgt not in graph:
                        continue
                    try:
                        for path in nx.all_simple_paths(graph, source=src, target=tgt, cutoff=cutoff):
                            path_set.add(tuple(path))
                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        pass
            return path_set

        baseline_paths = _count_paths(self.G)
        baseline_count = len(baseline_paths)

        if baseline_count == 0:
            return {"message": "No attack paths to analyse.", "recommendation": "Cluster appears secure."}

        # Step 2: For each intermediate node, measure impact of removal
        # We exclude source and target nodes themselves (can't patch the internet or the DB)
        excluded = set(sources) | set(crown_jewels)
        candidates = [n for n in self.G.nodes() if n not in excluded]

        best_node = None
        max_reduction = 0
        best_reduction_detail = {}

        for node in candidates:
            G_temp = self.G.copy()
            G_temp.remove_node(node)
            remaining_paths = _count_paths(G_temp)
            reduction = baseline_count - len(remaining_paths)

            if reduction > max_reduction:
                max_reduction = reduction
                best_node = node
                best_reduction_detail = {
                    "paths_eliminated": reduction,
                    "paths_remaining": len(remaining_paths),
                }

        if best_node is None:
            return {
                "message": "No single node removal significantly reduces attack paths.",
                "recommendation": "Apply defence-in-depth: harden multiple nodes simultaneously.",
            }

        node_data = self.G.nodes[best_node]
        node_type = node_data.get('type', 'unknown')

        from config import REMEDIATION_MAP
        # Pick remediation hint based on node type or fall back to default
        hint_key = {
            "ServiceAccount": "runs-as-sa",
            "Role": "wildcard-rbac",
            "ClusterRole": "wildcard-rbac",
            "Node": "node-admin",
            "Secret": "secret-reader",
        }.get(node_type, "default-remediation")
        hint = REMEDIATION_MAP.get(hint_key, REMEDIATION_MAP["default-remediation"])

        recommendation = (
            f"Recommendation: Remove or restrict '{best_node}' "
            f"({node_type}) to eliminate {max_reduction} of {baseline_count} attack paths. "
            f"— {hint}"
        )

        return {
            "node": best_node,
            "node_type": node_type,
            "paths_eliminated": max_reduction,
            "total_paths": baseline_count,
            "recommendation": recommendation,
        }


# ==========================================
# CLI REPORT GENERATOR
# ==========================================

def find_all_attack_paths(graph, sources, crown_jewels, cutoff=8):
    """Enumerates all attack paths from any source to any crown jewel."""
    all_paths = []
    for source in sources:
        for target in crown_jewels:
            try:
                for p in nx.all_simple_paths(graph.G, source=source, target=target, cutoff=cutoff):
                    risk = sum(graph.G[u][v].get('risk_score', 0) for u, v in zip(p[:-1], p[1:]))
                    all_paths.append({
                        "source": source,
                        "target": target,
                        "path": p,
                        "total_risk_score": round(risk, 2),
                        "total_hops": len(p) - 1,
                    })
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
    return all_paths


def generate_report(graph, blast_radius_node=None):
    entry_points = graph.get_entry_points()
    crown_jewels = graph.get_crown_jewels()

    if not crown_jewels:
        print("[!] No crown jewels found in the cluster graph.")
        return

    # ---- Collect all paths ----
    all_detected_paths = find_all_attack_paths(graph, entry_points, crown_jewels)

    # Assumed Breach: also scan from every Pod
    print("[*] Running 'Assumed Breach' lateral movement scan...")
    all_pods = [n for n, d in graph.G.nodes(data=True) if d.get('type') == 'Pod']
    all_detected_paths += find_all_attack_paths(graph, all_pods, crown_jewels)

    # Deduplicate and sort by risk (descending)
    unique = {tuple(p['path']): p for p in all_detected_paths}
    all_detected_paths = sorted(unique.values(), key=lambda x: x['total_risk_score'], reverse=True)

    print("\n" + "=" * 60)
    print("KILL CHAIN LIST".center(60))
    print("=" * 60 + "\n")

    worst_path = None
    critical_res = {"message": "Cluster is currently secure."}

    if not all_detected_paths:
        print("✅ SECURE: No exploitable paths found.")
    else:
        worst_path = all_detected_paths[0]

        for idx, p_data in enumerate(all_detected_paths[:5]):
            score = p_data['total_risk_score']
            severity = "CRITICAL" if score >= 15 else "HIGH" if score >= 8 else "MEDIUM"
            print(f"[Path #{idx+1}] {severity} (Risk: {score})")
            print(f"  Entry: {p_data['source']}")
            for u, v in zip(p_data['path'][:-1], p_data['path'][1:]):
                print(f"    → [{graph.G[u][v].get('relation', '?')}] {v}")
            print("-" * 30)

    # ---- Blast Radius ----
    if blast_radius_node and blast_radius_node not in graph.G:
        print(f"\n[!] Node '{blast_radius_node}' not found. Falling back to default.")
        blast_radius_node = None

    blast_source = (
        blast_radius_node
        or (worst_path["source"] if worst_path else None)
        or (entry_points[0] if entry_points else None)
    )
    blast = {"total_reachable": 0, "max_hops_checked": 3}
    if blast_source:
        blast = graph.get_blast_radius(blast_source)
        if "error" not in blast:
            print(f"\n✓ Blast Radius of '{blast_source}': {blast['total_reachable']} resources within {blast['max_hops_checked']} hops")

    # ---- Cycle Detection ----
    cycles = graph.detect_cycles()
    print(f"✓ Cycles Detected: {len(cycles)}")

    # ---- Task 4: Critical Node (FIXED) ----
    print("\n" + "=" * 60)
    print("CRITICAL NODE ANALYSIS (Task 4)".center(60))
    print("=" * 60)
    all_sources = entry_points + all_pods
    critical_res = graph.identify_critical_node(all_sources, crown_jewels)
    print(critical_res.get("recommendation") or critical_res.get("message"))
    if "paths_eliminated" in critical_res:
        print(f"  Impact: removes {critical_res['paths_eliminated']} of {critical_res['total_paths']} attack paths")

    # ---- Remediations ----
    print("\n" + "=" * 60)
    print("TOP REMEDIATIONS".center(60))
    print("=" * 60)
    if all_detected_paths:
        seen = set()
        from config import REMEDIATION_MAP
        for p_data in all_detected_paths[:5]:
            for u, v in zip(p_data['path'][:-1], p_data['path'][1:]):
                rel = graph.G[u][v].get('relation', '')
                if rel in REMEDIATION_MAP and rel not in seen:
                    print(f"• [{rel}]: {REMEDIATION_MAP[rel]}")
                    seen.add(rel)
        if not seen:
            print("• Apply general RBAC hardening and Pod Security Admission policies.")
    else:
        print("No remediations required.")
    print("=" * 60 + "\n")

    # ---- Exports ----
    from cli_ui_components import display_rich_dashboard
    display_rich_dashboard(worst_path, blast, cycles, critical_res, graph)

    # FIX: pass graph separately to PDF — don't store it inside path dicts
    export_full_pdf_report(all_detected_paths, graph)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kubernetes Attack Path Visualizer - Graph Engine")
    parser.add_argument("-i", "--input", default="cluster-graph.json")
    parser.add_argument("-b", "--blast-node", default=None)
    args = parser.parse_args()

    ag = AttackPathGraph()
    if ag.load_from_json(args.input):
        generate_report(ag, blast_radius_node=args.blast_node)
