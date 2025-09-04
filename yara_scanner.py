# yara_scanner.py

import yara
import os

# Regras YARA básicas para detectar ransomwares conhecidos.
# Em um projeto real, o ideal é carregar estas regras de um arquivo .yar
# e usar um conjunto de regras mais completo de fontes como a comunidade open-source.
YARA_RULES = """
rule Ransomware_Note_Filenames {
    meta:
        description = "Detecta nomes comuns de arquivos de nota de resgate de ransomware"
        author = "Parceiro de Programacao"
    strings:
        $ransom_note1 = /DECRYPT_INSTRUCTIONS\.(txt|html)/
        $ransom_note2 = /RECOVERY_FILES\.txt/
        $ransom_note3 = /HELP_DECRYPT\.txt/
        $ransom_note4 = /HOW_TO_DECRYPT_FILES\.txt/
        $ransom_note5 = /restore_files_.*\.txt/
    condition:
        // A regra é acionada se o NOME DO ARQUIVO corresponder a um dos padrões
        (for any of them : ( uint32(0) == uint32be(0x23212F62) or filesize < 10KB and @ransom_note1[0] == 0)) or
        filename matches /(DECRYPT|RECOVER|RESTORE|HELP)_/i
}

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
        Se houver um erro de sintaxe nas regras, uma exceção será levantada.
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
        Escaneia um único arquivo com as regras YARA compiladas.

        Args:
            file_path (str): O caminho para o arquivo a ser escaneado.

        Returns:
            bool: True se uma correspondência for encontrada, False caso contrário.
        """
        if not self.rules or not os.path.exists(file_path):
            return False
        
        try:
            matches = self.rules.match(filepath=file_path)
            if matches:
                print(f"🚨 AMEAÇA YARA DETECTADA! Arquivo: '{file_path}'. Regra(s): {[match.rule for match in matches]}")
                return True
        except yara.Error:
            # Pode ocorrer um erro se o arquivo for bloqueado ou excluído durante o escaneamento
            return False
        
        return False