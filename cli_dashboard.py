import time
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich.align import Align

# Import your existing logic
from final_data_collector import UnifiedK8sCollector
from final_graph_builder import AttackPathGraph, generate_report
from config import RESOURCE_TYPES

console = Console()

def display_splash():
    """Renders a high-tech ASCII splash screen."""
    ascii_art = r"""
    [bold cyan]
██████  ██   ██  █████  ██████   ██████  ██     ██ 
██       ██   ██ ██   ██ ██   ██ ██    ██ ██     ██ 
 ██████  ███████ ███████ ██   ██ ██    ██ ██  █  ██ 
      ██ ██   ██ ██   ██ ██   ██ ██    ██ ██ ███ ██ 
 ██████  ██   ██ ██   ██ ██████   ██████   ███ ███  

████████ ██████   █████   ██████ ███████ ██████  
   ██    ██   ██ ██   ██ ██      ██      ██   ██ 
   ██    ██████  ███████ ██      █████   ██████  
   ██    ██   ██ ██   ██ ██      ██      ██   ██ 
   ██    ██   ██ ██   ██  ██████ ███████ ██   ██
    [/bold cyan]
    """
    console.print(Align.center(ascii_art))
    console.print(Align.center("[bold white]Kubernetes Attack Path Visualizer & Risk Analyzer[/bold white]"))
    console.print(Align.center("[dim]Phase 1: Data Ingestion | Phase 2: Graph Analysis[/dim]"))
    console.print("\n")

def run_ingestion_with_progress():
    """Wraps the Phase 1 collector in a Rich progress bar."""
    collector = UnifiedK8sCollector()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        
        # Overall cluster scan task
        overall_task = progress.add_task("[yellow]Scanning Cluster...", total=len(RESOURCE_TYPES))
        
        # We manually trigger the fetch steps to update the UI
        print("[*] Initializing concurrent collection...")
        
        # Instead of calling fetch_all_concurrently, we loop so we can update the bar
        with collector.executor_class(max_workers=6) as executor:
            futures = {executor.submit(collector.run_kubectl_json, r): r for r in RESOURCE_TYPES}
            for future in collector.as_completed_func(futures):
                res_name = futures[future]
                collector.snapshot[res_name] = future.result()
                progress.update(overall_task, advance=1, description=f"[green]Fetched {res_name}")
                time.sleep(0.1) # Brief pause for visual effect

    collector.process_cluster_data()
    collector.export("cluster-graph.json")
    return collector

def run_analysis_dashboard():
    """Runs the full pipeline and displays the final CLI dashboard."""
    display_splash()
    
    # 1. Ingestion
    collector = run_ingestion_with_progress()
    
    # 2. Graph Construction
    console.print("\n[bold blue][*] Building Attack Graph...[/bold blue]")
    ag = AttackPathGraph()
    if not ag.load_from_json("cluster-graph.json"):
        console.print("[bold red][!] Graph Construction Failed.[/bold red]")
        return

    # 3. Final Report (We'll adapt this next to use Rich tables)
    console.print("[bold green][+] Analysis Complete. Generating Report...[/bold green]\n")
    generate_report(ag) # This currently prints the standard CLI report

if __name__ == "__main__":
    try:
        run_analysis_dashboard()
    except KeyboardInterrupt:
        console.print("\n[bold red]Terminated by user.[/bold red]")