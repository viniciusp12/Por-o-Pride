# yara_scanner.py

import yara
import os

# Versão final e simplificada das regras YARA.
# Focada apenas no conteúdo do arquivo para garantir compatibilidade.
YARA_RULES = r"""
rule WannaCry_Strings {
    meta:
        description = "Detecta strings específicas associadas ao WannaCry"
        author = "Parceiro de Programacao"
    strings:
        $s1 = "Wana Decrypt0r" wide
        $s2 = "wanacryptor" ascii
        $s3 = "wcry@123" wide
    condition:
        any of them
}
"""

class YaraScanner:
    def __init__(self):
        """
        Compila as regras YARA na inicialização.
        """
        try:
            print("Compilando regras YARA...")
            self.rules = yara.compile(source=YARA_RULES)
            print("Regras YARA compiladas com sucesso.")
        except yara.Error as e:
            print(f"Erro ao compilar regras YARA: {e}")
            self.rules = None

    def scan_file(self, file_path: str) -> bool:
        """
        Escaneia o CONTEÚDO de um único arquivo com as regras YARA compiladas.
        """
        if not self.rules or not os.path.exists(file_path):
            return False
        
        try:
            matches = self.rules.match(filepath=file_path)
            if matches:
                print(f"🚨 AMEAÇA YARA DETECTADA (CONTEÚDO)! Arquivo: '{file_path}'. Regra(s): {[match.rule for match in matches]}")
                return True
        except yara.Error:
            # Pode ocorrer um erro se o arquivo for bloqueado, por isso retornamos False.
            return False
        
        return False