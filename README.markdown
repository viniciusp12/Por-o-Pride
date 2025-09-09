# 🛡️ Porão Anti-Ransomware

Uma ferramenta de segurança proativa para Windows, desenvolvida em Python, projetada para detectar e neutralizar ataques de ransomware em tempo real. A solução utiliza uma abordagem de defesa em camadas com foco na análise de comportamento para identificar e mitigar ameaças, incluindo variantes desconhecidas (ataques de dia zero).

## 🚀 Principais Funcionalidades

- **📂 Monitoramento em Tempo Real**: Vigia continuamente diretórios críticos do usuário (Documentos, Downloads, Desktop, etc.), incluindo pastas temporárias do sistema.
- **🔎 Análise Heurística**: Detecta criação, modificação ou exclusão massiva de arquivos em alta velocidade.
- **🎯 Canary Files (Arquivos Isca)**: Dispara um alerta imediato e de alta prioridade caso arquivos "isca" pré-configurados sejam modificados.
- **🎲 Análise de Entropia**: Mede a aleatoriedade do conteúdo de um arquivo para detectar o processo de criptografia em tempo real.
- **🔬 Verificação de Hash**: Compara o hash de novos executáveis com o banco de dados online da MalwareBazaar para identificar malwares conhecidos.
- **📜 Regras YARA**: Utiliza um conjunto customizável de regras YARA para detectar famílias de ameaças conhecidas através de assinaturas e padrões em arquivos.
- **👨‍💻 Monitoramento de Comandos (Ataque Preventivo)**: Bloqueia proativamente a execução de processos a partir de pastas de risco (ex: Temp) e detecta comandos suspeitos, como tentativas de apagar cópias de sombra (vssadmin).
- **⚡ Resposta Automática Inteligente**: Ao detectar uma ameaça, encerra imediatamente a árvore de processos maliciosos e ativa um sistema de análise de snapshot para encontrar e colocar em quarentena todo o dano causado (arquivos novos ou modificados).
- **🔄 Persistência como Serviço**: Um script de instalação registra a ferramenta no Agendador de Tarefas do Windows para iniciar automaticamente com o sistema, rodando de forma invisível e com privilégios máximos (SYSTEM).

## ⚙️ Como Funciona: Documentação Técnica

A ferramenta opera sob o princípio de **Defesa em Profundidade**, utilizando uma arquitetura híbrida que combina vigilância proativa de processos com monitoramento reativo de arquivos em tempo real.

### A Arquitetura Híbrida

O sistema funciona com dois "motores" principais em paralelo:

1. **O Vigilante Proativo (novos_processos)**: 
   - É o "caçador" da ferramenta. Um loop de alta frequência (a cada 0.05 segundos) patrulha ativamente o sistema em busca de comportamentos suspeitos de processos, agindo antes que modifiquem arquivos.
   - Foca em bloquear execuções de locais proibidos e detectar comandos perigosos como `vssadmin delete shadows`.

2. **O Sensor Reativo (MonitorFolder com watchdog)**:
   - É o "alarme de perímetro". Notificado em tempo real pelo sistema operacional sobre qualquer criação ou modificação de arquivos, ele serve como o gatilho mais rápido para ataques que já começaram a interagir com os dados.
   - Suas detecções (Canary Files, Entropia, YARA, etc.) são consideradas de alta prioridade.

### O Protocolo de Resposta Unificado (encerrar_proctree)

Qualquer detecção, seja do Vigilante Proativo ou do Sensor Reativo, aciona o mesmo protocolo de resposta centralizado, garantindo uma ação sempre completa e poderosa em 3 passos:

1. **Análise de Dano via Snapshot (analisar_diferenca_e_agir)**:
   - Compara o estado atual dos arquivos com um "mapa" seguro (snapshot) criado anteriormente.
   - Tudo que foi criado ou modificado desde o último snapshot é considerado parte do ataque e movido para a quarentena, garantindo a contenção completa do dano.

2. **Neutralização do Processo**:
   - Usa o comando `taskkill` para forçar o encerramento da árvore de processos de todos os suspeitos recentes.
   - Uma lógica de autoproteção impede que o antivírus encerre a si mesmo.

3. **Recuperação e Re-armação**:
   - Após 10 segundos para estabilização, a ferramenta cria um novo snapshot "limpo", estabelecendo uma nova linha de base segura para continuar o monitoramento.

## 🛠️ Instalação e Uso

### 🔑 Pré-requisitos

- **Sistema Operacional**: Windows 10 ou superior
- **Python**: 3.8+ (adicionado ao PATH do sistema)
- **Permissões**: É necessário executar os scripts a partir de um terminal com privilégios de Administrador.

### 📥 Passos para Instalação

1. **Clone o repositório (ou baixe o ZIP e extraia os arquivos)**:
   ```bash
   git clone https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git
   cd SEU_REPOSITORIO
   ```

2. **Crie a pasta de regras YARA**:
   Dentro da pasta do projeto, crie uma subpasta chamada `rules`:
   ```bash
   mkdir rules
   ```

3. **Adicione as regras YARA**:
   - Baixe os arquivos de regras (.yar) de repositórios confiáveis (como o [signature-base](https://github.com/Neo23x0/signature-base)) e coloque-os na pasta `rules`.
   - Crie um arquivo `index.yar` que inclua as regras que você baixou. Exemplo:
     ```yara
     include "GEN_Ransomware.yar"
     include "Crime_Generic.yar"
     ```

4. **Instale as dependências**:
   Execute o seguinte comando no seu terminal:
   ```bash
   pip install psutil yara-python requests watchdog regex
   ```

### 🚀 Como Executar

#### ▶️ Execução Manual (Para Testes)

Para iniciar o monitoramento em tempo real para uma sessão de teste, execute a partir de um terminal de Administrador:
```bash
python porao.py
```

#### ⚙️ Instalação como Serviço (Recomendado para Proteção Real)

Para que a ferramenta inicie automaticamente com o Windows e permaneça ativa, execute o instalador uma única vez a partir de um terminal de Administrador:
```bash
python instalar_servico.py
```

Isso registrará a ferramenta no Agendador de Tarefas, garantindo que o monitoramento comece em cada inicialização, rodando de forma invisível e com privilégios máximos.

#### 📝 Customizar Arquivos Isca (Opcional)

1. Abra o arquivo `porao.py`.
2. Edite a lista `CANARY_FILES` com os arquivos/diretórios que deseja usar como isca.
3. Se os arquivos não existirem, o script os criará automaticamente na primeira execução.

## ⚠️ Aviso Legal

- Esta ferramenta **encerra processos críticos** — use com responsabilidade.
- A instalação e execução requerem **privilégios de Administrador**.
- Projeto desenvolvido para **fins educacionais e de defesa cibernética**.
- O **uso indevido** é de inteira responsabilidade do usuário.
- 🚫 **É estritamente proibida qualquer forma de venda ou comercialização deste projeto**. Ele é de autoria exclusiva do desenvolvedor.