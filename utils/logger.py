from datetime import datetime
from rich.table import Table

class CommandLogger:
    def __init__(self, max_history=100):
        self.command_history = []
        self.max_history = max_history
    
    def log_command(self, session_id, command):
        """Registra um comando no histórico"""
        self.command_history.append({
            'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'session': session_id,
            'command': command
        })
        # Manter apenas os últimos max_history comandos
        if len(self.command_history) > self.max_history:
            self.command_history.pop(0)
    
    def show_history(self, limit, console):
        """Mostra o histórico de comandos"""
        if not self.command_history:
            console.print("[yellow]Nenhum comando no histórico[/yellow]")
            return
            
        table = Table(title=f"Últimos {limit} Comandos", show_header=True, header_style="bold blue")
        table.add_column("Hora", style="cyan", no_wrap=True)
        table.add_column("Sessão")
        table.add_column("Comando", style="green")
        
        for cmd in self.command_history[-limit:]:
            table.add_row(cmd['time'], str(cmd['session']), cmd['command'])
            
        console.print(table)
