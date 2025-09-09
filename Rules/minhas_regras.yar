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