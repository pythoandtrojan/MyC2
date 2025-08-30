from rich.panel import Panel

def display_banner(console, host, port):
    banner = """
██████╗ ██████╗ 
██╔══██╗╚════██╗
██████╔╝ █████╔╝
██╔══██╗██╔═══╝ 
██████╔╝███████╗
╚═════╝ ╚══════╝
COMMAND & CONTROL SERVER v4.0
"""
    console.print(Panel.fit(
        f"[bold red]{banner}[/bold red]",
        title="[bold white on red] C2 SERVER [/bold white on red]",
        border_style="red",
        padding=(1, 2)
    ))
    
    console.print(Panel.fit(
        f"[yellow]⚠️  SERVIDOR: {host}:{port} - USE APENAS PARA FINS EDUCACIONAIS! ⚠️[/yellow]",
        border_style="yellow"
    ))
