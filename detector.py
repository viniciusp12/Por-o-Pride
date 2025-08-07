import requests
import hashlib
import winreg
import os


class Hash():
    def __init__(self, last_file: str) -> str:
        self.malware = False
        self.last_file = last_file

    def gerar_Hash(self): # hash do ultimo arquivo
        sha256 = hashlib.sha256()
        with open(self.last_file, "rb") as file:
            for x in iter(lambda: file.read(4094), b""):
                sha256.update(x)
        return sha256.hexdigest()
        

class ColetaDados(Hash):
    def __init__(self, last_file) -> str:
        super().__init__(last_file)
        self.url = "https://mb-api.abuse.ch/api/v1/"
        self.malware_info = {}
        self.dataBase_Search()
        
    def dataBase_Search(self):
        errors = ["illegal_hash", "hash_not_found"]
        hash = self.gerar_Hash()
        data = {
            "query":"get_info",
            "hash": hash
            }
        r = requests.post(url=self.url, data=data).json()
        if r["query_status"] in errors:
            self.malware = False
        else:
            self.malware_info["signature"] = r["data"][0]["signature"]
            self.malware_info["sha256"] = r["data"][0]["sha256_hash"]
            self.malware_info["locate"] = self.last_file
            self.malware = True


class DetectorMalware(ColetaDados):
    def __init__(self, last_file) -> str:
        super().__init__(last_file)
        self.main()

    def main(self):
        if self.malware:
            print(f'\nFoi encontrado um Malware!\n{"-"*20}\nSignature: {self.malware_info["signature"]}\nSHA256: {self.malware_info["sha256"]}\nLocate: {self.malware_info["locate"]}\n{"-"*20}')
            #os.remove(self.last_file)
        else:
            print("\nNão foi detectado nenhum Malware!\n")
