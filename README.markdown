# 🛡️ Porão Anti-Ransomware

Uma ferramenta de segurança proativa para **Windows**, desenvolvida em **Python**, projetada para detectar e neutralizar ataques de **ransomware em tempo real**. A solução utiliza uma abordagem de **defesa em camadas** com foco na **análise de comportamento** para identificar e mitigar ameaças, incluindo variantes desconhecidas (**ataques de dia zero**).

---

## 🚀 Principais Funcionalidades

- 📂 **Monitoramento em Tempo Real**: Vigia continuamente diretórios críticos do usuário (Documentos, Downloads, Desktop, etc.).
- 🔎 **Análise Heurística**: Detecta criação, modificação ou exclusão massiva de arquivos.
- 🎯 **Canary Files (Arquivos Isca)**: Dispara alerta imediato caso arquivos isca sejam modificados.
- 🎲 **Análise de Entropia**: Mede a aleatoriedade dos arquivos (possível criptografia).
- 🔬 **Verificação de Hash**: Compara executáveis com a base do [MalwareBazaar](https://bazaar.abuse.ch/).
- 📜 **Regras YARA**: Detecta famílias conhecidas de ransomware (ex: WannaCry).
- 👨‍💻 **Monitoramento de Comandos**: Bloqueia tentativas de apagar cópias de sombra (`vssadmin`).
- ⚡ **Resposta Automática**: Encerra imediatamente a árvore de processos maliciosos.
- 🔄 **Persistência como Serviço**: Inicia automaticamente com o Windows.

---

## ⚙️ Como Funciona

O script principal **`porao.py`** inicia um observador que monitora o sistema de arquivos. Cada evento (criação, modificação, exclusão) passa pelas camadas de detecção. Se uma regra crítica for acionada (ex: alteração de arquivo isca ou alta entropia), o protocolo **`encerrar_proctree()`** é chamado para neutralizar a ameaça.

---

## 🛠️ Instalação

### 🔑 Pré-requisitos
- **Sistema Operacional**: Windows 10 ou superior
- **Python**: 3.8+ (adicionado ao PATH)
- **Git**: Opcional, para clonar o repositório
- **Permissões**: Administrador (necessário para instalação como serviço)

### 📥 Passos

1. **Clone o repositório** (ou baixe o ZIP e extraia os arquivos):
   ```bash
   git clone https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git
   cd SEU_REPOSITORIO
   ```

2. **Instale as dependências**:
   ```bash
   pip install psutil yara-python requests watchdog regex
   ```

---

## 🚀 Como Usar

### ▶️ Execução Manual
Para iniciar o monitoramento em tempo real, execute:
```bash
python porao.py
```

### ⚙️ Instalação como Serviço (Opcional)
⚠️ **Necessário executar como Administrador**

Para que a ferramenta inicie automaticamente com o Windows:
```bash
python instalar_servico.py
```
Isso registrará a ferramenta no **Agendador de Tarefas**, garantindo que o monitoramento comece em cada inicialização.

### 📝 Customizar Arquivos Isca (Opcional)
1. Abra o arquivo `porao.py`.
2. Edite a lista `CANARY_FILES` com os arquivos/diretórios que deseja usar como isca.
3. Se os arquivos não existirem, o script os criará automaticamente.

---

## ⚠️ Aviso Legal

- Esta ferramenta **encerra processos críticos** — use com responsabilidade.
- A instalação como serviço requer **privilégios de Administrador**.
- Projeto desenvolvido para **fins educacionais e de defesa cibernética**.
- O **uso indevido** é de inteira responsabilidade do usuário.
- 🚫 **É estritamente proibida qualquer forma de venda ou comercialização deste projeto. Ele é de autoria exclusiva do desenvolvedor.**
