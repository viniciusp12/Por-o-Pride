# detector.py

import requests
import hashlib
import os

class Hash:
    def __init__(self, last_file: str):
        self.malware_detected = False
        self.last_file = last_file

    def gerar_Hash(self):
        sha256 = hashlib.sha256()
        try:
            with open(self.last_file, "rb") as file:
                for x in iter(lambda: file.read(4094), b""):
                    sha256.update(x)
            return sha256.hexdigest()
        except (FileNotFoundError, PermissionError):
            return None

class ColetaDados(Hash):
    def __init__(self, last_file):
        super().__init__(last_file)
        self.url = "https://mb-api.abuse.ch/api/v1/"
        self.malware_info = {}
        self.dataBase_Search()
        
    def dataBase_Search(self):
        file_hash = self.gerar_Hash()
        if not file_hash:
            return

        data = {
            "query": "get_info",
            "hash": file_hash
        }
        
        try:
            r = requests.post(url=self.url, data=data, timeout=5).json()
            # CORREÇÃO PRINCIPAL:
            # Agora verificamos se o status é 'ok' E se a chave 'data' realmente existe.
            if r.get("query_status") == 'ok' and r.get('data'):
                self.malware_info["signature"] = r["data"][0].get("signature", "N/A")
                self.malware_info["sha256"] = r["data"][0].get("sha256_hash", "N/A")
                self.malware_info["locate"] = self.last_file
                self.malware_detected = True
        except (requests.RequestException, KeyError):
            # Se a API falhar ou a resposta for malformada, simplesmente ignoramos.
            self.malware_detected = False

class DetectorMalware:
    def __init__(self, last_file: str):
        self.coleta = ColetaDados(last_file)

    def is_malware(self) -> bool:
        if self.coleta.malware_detected:
            print(f'\n🚨 MALWARE DETECTADO (HASH)!')
            print(f'{"-"*20}')
            print(f'Signature: {self.coleta.malware_info["signature"]}')
            print(f'SHA256: {self.coleta.malware_info["sha256"]}')
            print(f'Local: {self.coleta.malware_info["locate"]}')
            print(f'{"-"*20}')
            return True
        return False