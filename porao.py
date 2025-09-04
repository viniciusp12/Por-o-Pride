# porao.py

from detector import DetectorMalware
from yara_scanner import YaraScanner
import os
import pathlib
import psutil
import time
import subprocess
import regex as re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import RegistroAdd as registry
import sys

# --- VARIÁVEIS GLOBAIS ---
username = os.getlogin()
ult_processos = []  # Guarda PIDs de processos criados recentemente
change_type = [0, 0, 0, 0, 0]
# [0] - arquivos_criados, [1] - arquivos_mods, [2] - arquivos_movs, [3] - arquivos_delets, [4] - arquivos_honeypot_editados
last_activity_time = time.time()
active_threat = False # Flag para evitar múltiplas execuções da mitigação

# --- FUNÇÕES DE DETECÇÃO E PROTEÇÃO ---

def check_ransom_note_filename(file_path: str) -> bool:
    """
    Verifica se o nome do arquivo corresponde a padrões de notas de resgate de ransomware.
    Esta função assume a lógica que antes estava na regra YARA.
    """
    filename = os.path.basename(file_path)
    # Expressão regular para encontrar nomes como 'DECRYPT_INSTRUCTIONS.txt', 'HOW_TO_RECOVER_FILES.html', etc.
    pattern = re.compile(r'((DECRYPT|RECOVER|RESTORE|HELP|INSTRUCTIONS).*\.(txt|html|hta))|restore_files_.*\.txt', re.IGNORECASE)
    if pattern.match(filename):
        print(f"\n🚨 AMEAÇA DETECTADA (NOME DE ARQUIVO)! Arquivo suspeito: '{filename}'")
        return True
    return False

def encerrar_proctree():
    global ult_processos, active_threat
    if active_threat:
        return # Se a mitigação já está em andamento, não faz nada
    
    active_threat = True
    print("\n" + "🚨 AMEAÇA DETECTADA! ACIONANDO PROTOCOLO DE MITIGAÇÃO! 🚨")
    pids_to_kill = ""
    for pid in reversed(ult_processos):
        if psutil.pid_exists(pid) and pid != os.getpid():
            pids_to_kill += f"/PID {pid} "
    
    if pids_to_kill:
        print(f"Encerrando processos suspeitos: {pids_to_kill}")
        subprocess.run(f"taskkill {pids_to_kill}/F /T", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    ult_processos.clear()
    print("Processos encerrados. O sistema pode precisar de reinicialização.")
    time.sleep(10) # Pausa para evitar re-acionamento imediato
    active_threat = False

def avaliar_heuristica():
    global change_type
    criados, modificados, movidos, deletados, honeypot = change_type

    if honeypot > 0:
        print("\nHeurística: Modificação em arquivo honeypot detectada!")
        return True
    if modificados > 30 and criados > 10:
        print("\nHeurística: Alto volume de modificação e criação de arquivos!")
        return True
    if deletados > 50:
        print("\nHeurística: Alto volume de exclusão de arquivos!")
        return True
    return False

def extrair_extensao(file: str):
    extensions = [".exe", ".dll", ".com", ".bat", ".vbs", ".ps1"]
    file_extension = pathlib.Path(file).suffix
    return file_extension.lower() in extensions

def novos_processos():
    global ult_processos
    now = time.time()
    current_pids = []
    for process in psutil.process_iter(['pid', 'create_time']):
        try:
            if (now - process.info['create_time']) < 120: # Checa processos criados nos últimos 2 minutos
                if process.info['pid'] not in ult_processos:
                    ult_processos.append(process.info['pid'])
                current_pids.append(process.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    # Limpa PIDs de processos que já foram encerrados
    ult_processos = [pid for pid in ult_processos if pid in current_pids]

# --- CLASSE DE MONITORAMENTO ---
class MonitorFolder(FileSystemEventHandler):
    def __init__(self, yara_scanner: YaraScanner):
        self.yara_scanner = yara_scanner
        super().__init__()

    def on_any_event(self, event):
        global last_activity_time
        last_activity_time = time.time()
        if "porao" in event.src_path:
            change_type[4] += 1
        if avaliar_heuristica():
            encerrar_proctree()
    
    def on_created(self, event):
        if event.is_directory: return
        change_type[0] += 1
        
        # Verificando o nome do arquivo
        if check_ransom_note_filename(event.src_path):
            encerrar_proctree()
        
        # Verificando o conteúdo do arquivo
        if self.yara_scanner.scan_file(event.src_path):
            encerrar_proctree()
        
        # Verificando o hash de novos executáveis
        if extrair_extensao(event.src_path):
            detector = DetectorMalware(event.src_path)
            if detector.is_malware():
                encerrar_proctree()

    def on_deleted(self, event):
        change_type[3] += 1

    def on_modified(self, event):
        if event.is_directory: return
        change_type[1] += 1
        
        # Verificando o nome do arquivo
        if check_ransom_note_filename(event.src_path):
            encerrar_proctree()
        
        # Verificando o conteúdo do arquivo
        if self.yara_scanner.scan_file(event.src_path):
            encerrar_proctree()

    def on_moved(self, event):
        change_type[2] += 1

# --- EXECUÇÃO PRINCIPAL ---
if __name__ == "__main__":
    scanner = YaraScanner()
    if scanner.rules is None:
        print("Não foi possível iniciar o monitoramento sem as regras YARA.")
        exit()

    home_dir = os.path.expanduser('~')
    paths_to_watch = [
        os.path.join(home_dir, 'Downloads'),
        os.path.join(home_dir, 'Documents'),
        os.path.join(home_dir, 'Desktop'),
        os.path.join(home_dir, 'Pictures'),
    ]

    event_handler = MonitorFolder(yara_scanner=scanner)
    observer = Observer()
    
    print("Iniciando monitoramento...")
    for path in paths_to_watch:
        if os.path.exists(path):
            observer.schedule(event_handler, path=path, recursive=True)
            print(f" -> Monitorando: {path}")
        else:
            print(f" -> Aviso: O diretório '{path}' não existe e não será monitorado.")

    observer.start()
    
    spinner_states = ['-', '\\', '|', '/']
    spinner_index = 0
    
    try:
        while True:
            spinner_char = spinner_states[spinner_index]
            sys.stdout.write(f"\rMonitorando ativamente... {spinner_char}")
            sys.stdout.flush()
            spinner_index = (spinner_index + 1) % len(spinner_states)
            time.sleep(0.5) 
            novos_processos()
            # Reseta os contadores se não houver atividade por 15 segundos
            if time.time() - last_activity_time > 15:
                change_type = [0, 0, 0, 0, 0]
    except KeyboardInterrupt:
        print("\nMonitoramento encerrado pelo usuário.") 
        observer.stop()
    
    observer.join()