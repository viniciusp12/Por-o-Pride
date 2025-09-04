# porao.py

# MODIFICADO: Importa o novo scanner YARA e remove a importação do 'comportamento'
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

# --- VARIÁVEIS GLOBAIS ---
username = os.getlogin()
ult_processos = []  # Guarda PIDs de processos criados recentemente
change_type = [0, 0, 0, 0, 0]
# [0] - arquivos_criados, [1] - arquivos_mods, [2] - arquivos_movs, [3] - arquivos_delets, [4] - arquivos_honeypot_editados
last_activity_time = time.time()
active_threat = False # Flag para evitar múltiplas execuções da mitigação

# --- FUNÇÕES DE MITIGAÇÃO E PROTEÇÃO ---
def encerrar_proctree():
    global ult_processos, active_threat
    if active_threat:
        return # Se a mitigação já está em andamento, não faz nada
    
    active_threat = True
    print("🚨 AMEAÇA DETECTADA! ACIONANDO PROTOCOLO DE MITIGAÇÃO! 🚨")
    pids_to_kill = ""
    for pid in reversed(ult_processos):
        if psutil.pid_exists(pid) and pid != os.getpid():
            pids_to_kill += f"/PID {pid} "
    
    if pids_to_kill:
        print(f"Encerrando processos suspeitos: {pids_to_kill}")
        subprocess.run(f"taskkill {pids_to_kill}/F /T", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    ult_processos.clear()
    print("Processos encerrados. O sistema pode precisar de reinicialização.")
    # Poderia adicionar outras ações aqui, como desconectar a rede.
    time.sleep(10) # Pausa para evitar re-acionamento imediato
    active_threat = False

# NOVO: Função de análise heurística que substitui o modelo de ML
def avaliar_heuristica():
    global change_type
    criados, modificados, movidos, deletados, honeypot = change_type

    # Regra 1: Atividade de honeypot é um alerta máximo imediato
    if honeypot > 0:
        print("Heurística: Modificação em arquivo honeypot detectada!")
        return True

    # Regra 2: Atividade de modificação em massa (comportamento clássico de ransomware)
    if modificados > 30 and criados > 10:
        print("Heurística: Alto volume de modificação e criação de arquivos!")
        return True

    # Regra 3: Atividade de exclusão em massa (pode indicar tentativa de apagar originais)
    if deletados > 50:
        print("Heurística: Alto volume de exclusão de arquivos!")
        return True
    
    return False

def extrair_extensao(file: str):
    extensions = [".exe", ".dll", ".com", ".bat", ".vbs", ".ps1"]
    file_extension = pathlib.Path(file).suffix
    return file_extension.lower() in extensions

def start_protection():
    # ... (O conteúdo desta função pode permanecer o mesmo)
    # Recomendo revisar a parte de renomear vssadmin.exe se causar problemas
    pass # Removido para simplificar, mas a lógica original é válida

def honeypot():
    # ... (O conteúdo desta função permanece o mesmo)
    pass # Removido para simplificar

def shadow_copy():
    # ... (O conteúdo desta função permanece o mesmo)
    pass # Removido para simplificar

def novos_processos():
    global ult_processos
    now = time.time()
    current_pids = []
    for process in psutil.process_iter(['pid', 'create_time']):
        if (now - process.info['create_time']) < 120: # Aumentado para 2 minutos
            if process.info['pid'] not in ult_processos:
                ult_processos.append(process.info['pid'])
            current_pids.append(process.info['pid'])
    
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
        
        # Avaliação heurística a cada evento
        if avaliar_heuristica():
            encerrar_proctree()
    
    def on_created(self, event):
        if event.is_directory: return
        change_type[0] += 1
        
        # Escaneamento YARA em novos arquivos
        if self.yara_scanner.scan_file(event.src_path):
            encerrar_proctree()
        
        # Verificação de hash em novos executáveis
        if extrair_extensao(event.src_path):
            detector = DetectorMalware(event.src_path)
            if detector.is_malware():
                encerrar_proctree()

    def on_deleted(self, event):
        change_type[3] += 1

    def on_modified(self, event):
        if event.is_directory: return
        change_type[1] += 1

        # Escaneamento YARA em arquivos modificados
        if self.yara_scanner.scan_file(event.src_path):
            encerrar_proctree()

    def on_moved(self, event):
        change_type[2] += 1

# --- EXECUÇÃO PRINCIPAL ---
if __name__ == "__main__":
    # registry.AdicionarRegistro(name='PoraoRansomwareDetect') # Descomente para produção
    # start_protection()
    # shadow_copy()
    # honeypot()

    # NOVO: Instancia o scanner YARA
    scanner = YaraScanner()
    if scanner.rules is None:
        print("Não foi possível iniciar o monitoramento sem as regras YARA.")
        exit()

    # MODIFICADO: Lista de pastas críticas a serem monitoradas
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
    
    try:
        while True:
            time.sleep(5)
            novos_processos()
            
            # Reseta os contadores se não houver atividade por 15 segundos
            if time.time() - last_activity_time > 15:
                change_type = [0, 0, 0, 0, 0]
                
    except KeyboardInterrupt:
        print("\nMonitoramento encerrado pelo usuário.")
        observer.stop()
    
    observer.join()