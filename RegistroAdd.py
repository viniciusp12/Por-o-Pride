import winreg as reg
import ctypes, sys
import os            


def is_admin(): # request run as admin
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
        

def AdicionarRegistro(script=os.path.realpath(__file__), key=reg.HKEY_LOCAL_MACHINE, **kwarg):
    if is_admin():
        path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        open = reg.OpenKey(key, path, 0, reg.KEY_ALL_ACCESS)
        try:
            reg.SetValueEx(open, kwarg["name"],0,reg.REG_SZ, script) 
            reg.CloseKey(open)
        except KeyError:
            print("Defina um nome para o seu registro.")
        except Exception as err:
            print(err)
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)


if __name__=="__main__":
    path = ''
    AdicionarRegistro(script=path, name=" ") # Mudar nome e caminho