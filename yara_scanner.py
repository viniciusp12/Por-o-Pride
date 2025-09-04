# yara_scanner.py

import yara
import os

# CORRIGIDO: Usando r""" (raw string) para evitar avisos de sintaxe com '\'.
# E a regra Ransomware_Note_Filenames foi completamente reescrita para ser funcional.
YARA_RULES = r"""
rule Ransomware_Note_Filenames {
    meta:
        description = "Detecta nomes comuns de arquivos de nota de resgate de ransomware pelo nome do arquivo"
        author = "Parceiro de Programacao"
    condition:
        // A regra agora usa a keyword 'filename' para testar uma expressão regular contra o nome do arquivo.
        // Esta é a forma correta de fazer essa verificação em YARA.
        filename matches /((DECRYPT|RECOVER|RESTORE|HELP|INSTRUCTIONS).*\.(txt|html|hta))|restore_files_.*\.txt/i
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
            # CORRIGIDO: O escaneamento do nome do arquivo acontece aqui, dentro do 'match'
            matches = self.rules.match(filepath=file_path)
            if matches:
                print(f"🚨 AMEAÇA YARA DETECTADA! Arquivo: '{file_path}'. Regra(s): {[match.rule for match in matches]}")
                return True
        except yara.Error:
            return False
        
        return False
