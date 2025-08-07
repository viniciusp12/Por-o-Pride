from comportamento import avaliar
from detector import DetectorMalware
import os
import pathlib
import psutil
import time
import subprocess
import regex as re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import RegistroAdd as registry

data_list = []  # Guarda log de mudanças nos arquivos do sistema
users_list = []  # Coleta usuários da máquina
username = os.getlogin()  # Coleta o username
change_type = [0, 0, 0, 0, 0]
# arquivos_criados = 0  - Conta arquivos criados
# arquivos_mods = 1     - Conta arquivos modificados
# arquivos_movs = 2     - Conta arquivos movidos
# arquivos_delets = 3   - Conta arquivos deletados
# arquivos_edits = 4    - Conta arquivos editados
ult_processos = []  # Guarda processos criados nos últimos minutos
time_since_last_change = 100
last_shadow_backup = 0


def encerrar_proctree():  # Encerra o process tree e seus dependentes
    global ult_processos
    print("Possível Ransomware detectado!")
    pids = ""
    for pid in reversed(ult_processos):
        if pid != os.getpid():
            pids += f"/PID {pid} "
    subprocess.run(f"taskkill {pids}/F /T", shell=True)
    ult_processos.clear()


def extrair_extensao(file: str):
    extensions = [".exe", ".dll"]
    file_extension = pathlib.Path(file).suffix
    if file_extension.lower() in extensions:
        return True
    else:
        return False


def start_protection():  # Pasta de backup
    global users_list
    global username
    procname = psutil.Process(os.getpid()).name()
    subprocess.run(f'wmic process where name="{procname}" CALL setpriority "above normal"', shell=True)
    subprocess.run("mkdir protected_backup", shell=True)  # creating protected_folder
    subprocess.run("takeown /F C:\Windows\System32\\vssadmin.exe", shell=True)
    subprocess.run(f'icacls C:\Windows\System32\\vssadmin.exe /grant "{username}":F', shell=True)
    subprocess.run("ren C:\Windows\System32\\vssadmin.exe adminvss.exe", shell=True)
    get_users = subprocess.run("wmic useraccount get name", capture_output=True, shell=True)  # getting machine's users
    users = get_users.stdout.decode()
    users = re.split("/W|Name|\r|\n", users)
    for user in list(users):
        user = user.strip()
        if user == '':
            pass
        else:
            users_list.append(user)


def honeypot():  # Criar arquivos honeypot
    for x in range(1, 100):
        with open(f".porao{x}.txt", "w") as file:
            file.write("arquivo feito para detectar o ransomware")
        file.close()


def securing_files(folder):  # Negando acesso à todos usuários
    global users_list
    for user in users_list:
        subprocess.run(f'icacls "{folder}" /deny "{user}":R', shell=True)  # removing all users's permissions from folder


def destravar(folder):  # Habilitando acesso à todos usuários
    global users_list
    for user in users_list:
        subprocess.run(f'icacls "{folder}" /grant "{user}":R', shell=True)  # giving all users's permissions from folder


def shadow_copy():  # Cria uma shadowcopy a cada 1h30
    global last_shadow_backup
    global username
    now = time.time()
    if last_shadow_backup == 0:
        subprocess.run(f'xcopy "C:\\Users\\{username}\\Downloads" "C:\\Users\\{username}\\Downloads\\protected_backup" /Y', shell=True)  # creating backup copy
        subprocess.run("wmic shadowcopy delete", shell=True)  # deleting outdated shadowbackcup
        subprocess.run("wmic shadowcopy call create Volume='C:\\'", shell=True)  # creating shadowbackup
        last_shadow_backup = time.time()
        securing_files(f"C:\\Users\\{username}\\Downloads\\protected_backup")
    if now - last_shadow_backup >= 5400:
        subprocess.run("wmic shadowcopy delete", shell=True)  # deleting outdated shadowbackup
        subprocess.run("wmic shadowcopy call create Volume='C:\\'", shell=True)  # creating shadowbackup
        last_shadow_backup = time.time()


def novos_processos():  # Checar novos processos nos últimos minutos
    global ult_processos
    for process in psutil.process_iter():
        now = int(time.time())
        processtime = abs(process.create_time() - now)
        if processtime < 61:
            if process.pid not in ult_processos:
                ult_processos.append(process.pid)
        else:
            if process.pid in ult_processos:
                ult_processos.remove(process.pid)
    for process in ult_processos:
        if process not in psutil.process_iter():
            ult_processos.remove(process)


class MonitorFolder(FileSystemEventHandler):
    def on_any_event(self, event):
        global data_list
        global change_type
        if avaliar(change_type[0], change_type[1], change_type[2], change_type[3], change_type[4]):
            encerrar_proctree()
        if "porao" in event.src_path:
            change_type[4] += 1
        last_change = time.time(), event.src_path, event.event_type
        data_list.append(last_change)

    def on_created(self, event):
        global change_type
        change_type[0] += 1
        if "decrypt" in event.src_path.lower() or "restore" in event.src_path.lower() or "recover" in event.src_path.lower():
            print("Possível Ransomware detectado, arquivos de recuperação sendo criados.")
            try:
                encerrar_proctree()
            except:
                pass

    def on_deleted(self, event):
        global change_type
        change_type[3] += 1

    def on_modified(self, event):
        global change_type
        change_type[1] += 1
        if extrair_extensao(event.src_path):
            try:
                DetectorMalware(event.src_path)
            except:
                pass

    def on_moved(self, event):
        global change_type
        change_type[3] += 1


if __name__ == "__main__":
    registry.AdicionarRegistro(name='PoraoRansomwareDetect')
    start_protection()
    shadow_copy()
    honeypot()
    src_path = f"C:\\Users\\{username}\\Downloads"
    event_handler = MonitorFolder()
    observer = Observer()
    observer.schedule(event_handler, path=src_path, recursive=True)
    observer.start()
    try:
        while(True):
            try:
                if avaliar(change_type[0], change_type[1], change_type[2], change_type[3], change_type[4]):
                    encerrar_proctree()
                shadow_copy()
                novos_processos()
                time_since_last_change = abs(int(data_list[-1][0] - time.time()))
                if time_since_last_change > 10 or sum(change_type) > 20:
                    data_list.clear()
                    change_type = [0, 0, 0, 0, 0]
            except:
                pass
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
