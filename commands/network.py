def download_command(server, args):
    """Comando para download de arquivo"""
    if len(args) < 3:
        server.console.print("[red]Uso: download [id_sessão] [arquivo_remoto] [arquivo_local][/red]")
        return
        
    try:
        session_id = int(args[0])
        remote_file = args[1]
        local_file = args[2]
        
        server.console.print(f"[yellow]Solicitando download de {remote_file} para {local_file}[/yellow]")
        server.send_command(session_id, f"download {remote_file} {local_file}")
    except ValueError:
        server.console.print("[red]ID de sessão deve ser um número[/red]")

def upload_command(server, args):
    """Comando para upload de arquivo"""
    if len(args) < 3:
        server.console.print("[red]Uso: upload [id_sessão] [arquivo_local] [arquivo_remoto][/red]")
        return
        
    try:
        session_id = int(args[0])
        local_file = args[1]
        remote_file = args[2]
        
        server.console.print(f"[yellow]Solicitando upload de {local_file} para {remote_file}[/yellow]")
        server.send_command(session_id, f"upload {local_file} {remote_file}")
    except ValueError:
        server.console.print("[red]ID de sessão deve ser um número[/red]")

def port_forward_command(server, args):
    """Comando para encaminhamento de porta"""
    if len(args) < 4:
        server.console.print("[red]Uso: port_forward [id_sessão] [porta_local] [host_remoto] [porta_remota][/red]")
        return
        
    try:
        session_id = int(args[0])
        local_port = int(args[1])
        remote_host = args[2]
        remote_port = int(args[3])
        
        server.console.print(f"[yellow]Configurando encaminhamento de porta {local_port} -> {remote_host}:{remote_port}[/yellow]")
        server.send_command(session_id, f"port_forward {local_port} {remote_host} {remote_port}")
    except ValueError:
        server.console.print("[red]ID de sessão e portas devem ser números[/red]")

def socks5_command(server, args):
    """Comando para proxy SOCKS5"""
    if len(args) < 2:
        server.console.print("[red]Uso: socks5 [id_sessão] [start|stop] [porta][/red]")
        return
        
    try:
        session_id = int(args[0])
        action = args[1]
        
        if action == "start":
            port = 1080  # Porta padrão
            if len(args) > 2:
                port = int(args[2])
            server.console.print(f"[yellow]Iniciando proxy SOCKS5 na porta {port}[/yellow]")
            server.send_command(session_id, f"socks5_start {port}")
        elif action == "stop":
            server.console.print("[yellow]Parando proxy SOCKS5[/yellow]")
            server.send_command(session_id, "socks5_stop")
        else:
            server.console.print("[red]Ação deve ser 'start' ou 'stop'[/red]")
    except ValueError:
        server.console.print("[red]ID de sessão e porta devem ser números[/red]")
