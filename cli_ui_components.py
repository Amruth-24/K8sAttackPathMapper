from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.tree import Tree
from rich import box

console = Console()

def create_kill_chain_tree(worst_path, graph_ref):
    """Creates a visual vertical tree for the attack path."""
    if not worst_path:
        return Text("✅ No Attack Path Detected", style="bold green")

    path = worst_path["path"]
    # Starting Node
    tree = Tree(f"[bold red]Source: {path[0]}[/bold red]")
    
    curr_node = tree
    for u, v in zip(path[:-1], path[1:]):
        edge_data = graph_ref.G[u][v]
        rel = edge_data.get('relation', 'unknown')
        cve = f" [dim](CVE: {graph_ref.G.nodes[u].get('cve')})[/dim]" if graph_ref.G.nodes[u].get('cve') else ""
        
        # Add a branch for the next hop
        curr_node = curr_node.add(f"[yellow]→ [{rel}][/yellow] {v}{cve}")
    
    return curr_node

def display_rich_dashboard(worst_path, blast, cycles, critical_res, graph_ref):
    """Main function to render the high-fidelity results layout."""
    layout = Layout()

    # Split into Top (Header) and Bottom (Results)
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main", ratio=1)
    )

    # Split Main into Left (Kill Chain) and Right (Stats/Remediation)
    layout["main"].split_row(
        Layout(name="left", ratio=2),
        Layout(name="right", ratio=1)
    )

    # 1. Header
    layout["header"].update(
        Panel(Text("K8S ATTACK PATH ANALYSIS ENGINE - REPORT", justify="center", style="bold white on blue"), box=box.ROUNDED)
    )

    # 2. Left: Kill Chain
    kill_chain_visual = create_kill_chain_tree(worst_path, graph_ref)
    layout["left"].update(
        Panel(kill_chain_visual, title="[bold red]Critical Attack Path[/bold red]", border_style="red")
    )

    # 3. Right: Stats & Remediation
    stats_table = Table(show_header=False, box=box.SIMPLE, expand=True)
    if worst_path:
        severity = "CRITICAL" if worst_path['total_risk_score'] >= 15 else "HIGH"
        stats_table.add_row("[bold]Risk Level[/bold]", f"[bold red]{severity}[/bold red]")
        stats_table.add_row("[bold]Score[/bold]", f"{worst_path['total_risk_score']}")
        stats_table.add_row("[bold]Hops[/bold]", f"{worst_path['total_hops']}")
    
    stats_table.add_row("[bold]Blast Radius[/bold]", f"{blast.get('total_reachable', 0)} Nodes")
    stats_table.add_row("[bold]Cycles[/bold]", f"{len(cycles)}")

    remediation_text = Text(critical_res.get('recommendation', critical_res.get('message')), style="italic yellow")

    layout["right"].split_column(
        Layout(Panel(stats_table, title="[bold cyan]Analytics Summary[/bold cyan]", border_style="cyan")),
        Layout(Panel(remediation_text, title="[bold green]Remediation Strategy[/bold green]", border_style="green"))
    )

    console.print(layout)