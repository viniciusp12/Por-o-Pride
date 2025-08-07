import regex as re
import subprocess
import os

username = os.getlogin() #Pegar username
users_list = []
get_users = subprocess.run("wmic useraccount get name", capture_output=True, shell=True) #Pegando usuários da máquina
users = get_users.stdout.decode()
users = re.split("/W|Name|\r|\n", users)
for user in list(users):
    user = user.strip()
    if user == '':
        pass
    else:
        users_list.append(user)


def destravar(folder): #Permite usuários acessar a pasta segura
    global users_list
    for user in users_list:
        subprocess.run(f'icacls "{folder}" /grant "{user}":R', shell=True) #giving all users's permissions from folder


destravar(f"C:\\Users\\{username}\\Downloads\\protected_backup")
