import os
import sys
import subprocess
import ctypes

def is_admin():
    """Verifica se o script está sendo executado com privilégios de administrador."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def instalar_servico():
    """
    Cria uma tarefa no Agendador de Tarefas do Windows para rodar o script
    porao.py de forma persistente e invisível.
    """
    # Garante que o script só seja executado por um administrador
    if not is_admin():
        print("Erro: Este script precisa ser executado como Administrador.")
        print("Clique com o botão direito no arquivo e selecione 'Executar como administrador'.")
        input("Pressione Enter para sair...")
        return

    print("Iniciando a instalação do serviço de monitoramento...")

    try:
        # --- Define os caminhos de forma dinâmica ---
        # Caminho para o interpretador pythonw.exe (versão sem janela)
        # Usamos sys.executable para encontrar o python.exe atual e trocamos por pythonw.exe
        pythonw_path = sys.executable.replace("python.exe", "pythonw.exe")

        # Caminho completo para o script principal porao.py
        # __file__ se refere a este script (instalar_servico.py)
        # os.path.dirname encontra a pasta onde ele está
        script_dir = os.path.dirname(os.path.abspath(__file__))
        porao_script_path = os.path.join(script_dir, "porao.py")

        # Verifica se os arquivos necessários existem
        if not os.path.exists(pythonw_path):
            print(f"Erro: Não foi possível encontrar 'pythonw.exe' no caminho: {pythonw_path}")
            return
        if not os.path.exists(porao_script_path):
            print(f"Erro: O script 'porao.py' não foi encontrado na pasta: {script_dir}")
            return
            
        # --- Monta o comando para criar a tarefa ---
        nome_da_tarefa = "MonitorPoraoAntiRansomware"
        
        # O comando a ser executado pela tarefa. Aspas são importantes para caminhos com espaços.
        comando_executar = f'"{pythonw_path}" "{porao_script_path}"'

        # Comando completo do schtasks
        comando_schtasks = [
            "schtasks", "/Create",
            "/SC", "ONSTART",         # /SC ONSTART: Executa na inicialização do sistema
            "/TN", nome_da_tarefa,     # /TN: Nome da Tarefa
            "/TR", comando_executar,   # /TR: Tarefa a ser executada (Target Run)
            "/RU", "SYSTEM",           # /RU SYSTEM: Executa com o usuário 'SYSTEM', o mais alto privilégio
            "/RL", "HIGHEST",          # /RL HIGHEST: Garante os maiores privilégios
            "/F"                       # /F: Força a criação caso a tarefa já exista
        ]

        print(f"\nExecutando o comando para criar a tarefa:")
        print(" ".join(comando_schtasks))

        # Executa o comando no CMD e captura a saída
        resultado = subprocess.run(comando_schtasks, capture_output=True, text=True, check=True, shell=True)

        print("\n--- Resultado ---")
        print(resultado.stdout)
        print("Serviço instalado com sucesso!")
        print("O monitoramento será iniciado automaticamente na próxima vez que o computador ligar.")

    except subprocess.CalledProcessError as e:
        print("\n--- Ocorreu um Erro ---")
        print("Não foi possível criar a tarefa agendada.")
        print("Erro:", e.stderr)
    except Exception as e:
        print(f"\nOcorreu um erro inesperado: {e}")

    input("\nPressione Enter para finalizar...")


if __name__ == "__main__":
    instalar_servico()