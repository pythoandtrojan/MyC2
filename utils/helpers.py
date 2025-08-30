from rich.panel import Panel
from rich.text import Text

def display_banner(console, host, port):
    banner = Text("""
██████╗ ██████╗ 
██╔══██╗╚════██╗
██████╔╝ █████╔╝
██╔══██╗██╔═══╝ 
██████╔╝███████╗
╚═════╝ ╚══════╝
COMMAND & CONTROL SERVER v5.0
""", style="bold red")
    
    console.print(Panel.fit(
        banner,
        title="[bold white on red] C2 SERVER [/bold white on red]",
        border_style="red",
        padding=(1, 2)
    ))
    
    console.print(Panel.fit(
        f"[yellow]⚠️  SERVIDOR: {host}:{port} - USE APENAS PARA FINS EDUCACIONAIS! ⚠️[/yellow]",
        border_style="yellow"
    ))

def display_mini_banner(console):
    mini_banner = Text("""
╔══════════════════════════════════╗
║ C2 SERVER v5.0 - CONTROLE REMOTO ║
╚══════════════════════════════════╝
""", style="bold cyan")
    
    console.print(mini_banner)
