# 🛡️ CREDSCAN — Threat Intelligence Credential Scanner

> Ferramenta interna para equipes de **SOC** e **Threat Intelligence**, desenvolvida para identificar credenciais vazadas de domínios monitorados em grandes volumes de arquivos de dump, cruzando os achados com uma blacklist de itens já reportados.

<img width="740" height="853" alt="image" src="https://github.com/user-attachments/assets/72ab3c2c-0cf7-4ce4-a148-a4300fcbb4f4" />


---

## 📋 Índice

- [Sobre o projeto](#sobre-o-projeto)
- [Funcionalidades](#funcionalidades)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Estrutura esperada de arquivos](#estrutura-esperada-de-arquivos)
- [Como usar](#como-usar)
- [Parâmetros disponíveis](#parâmetros-disponíveis)
- [Entendendo os resultados](#entendendo-os-resultados)
- [Arquivo de saída](#arquivo-de-saída)
- [Fluxo de trabalho recomendado](#fluxo-de-trabalho-recomendado)
- [Domínios monitorados](#domínios-monitorados)
- [Como adicionar ou remover domínios](#como-adicionar-ou-remover-domínios)
- [Aviso legal](#aviso-legal)

---

## Sobre o projeto

O **CREDSCAN** foi desenvolvido para auxiliar analistas de Threat Intelligence no processo de monitoramento e reporte responsável de credenciais corporativas expostas em vazamentos de dados (*data leaks*).

O script percorre centenas (ou milhares) de arquivos `.txt` de dump — que geralmente contêm dados sujos e mal formatados — extrai pares `email:senha` válidos, filtra pelos domínios dos clientes monitorados e cruza os resultados com uma blacklist de credenciais já reportadas, evitando duplicidade nos reportes.

---

## Funcionalidades

- ✅ **Varredura em massa** — suporta diretórios com dezenas a centenas de GB de arquivos `.txt`
- ✅ **Limpeza automática de dados sujos** — extrai `email:senha` de linhas com URLs, pipes, separadores variados (`:` e `;`) e outros ruídos comuns em dumps
- ✅ **Filtro por domínio** — processa apenas e-mails dos domínios configurados
- ✅ **Verificação contra blacklist** — cruza cada achado com `blacklist.txt` antes de exibir
- ✅ **Deduplicação** — elimina pares repetidos entre arquivos diferentes
- ✅ **Progress bar em tempo real** — exibe progresso, contador de novos vs. já reportados e tempo decorrido
- ✅ **Interrupção segura com Ctrl+C** — exibe resultados parciais sem perda de dados
- ✅ **Exportação automática** — gera arquivo `.txt` com os novos achados ao final da execução
- ✅ **Resultado colorido no terminal** — verde para novos achados, vermelho para itens já reportados

---

## Pré-requisitos

- Python **3.10+** (utiliza `str | None` como type hint)
- Nenhuma biblioteca externa — apenas módulos da biblioteca padrão do Python

Para verificar sua versão:
```bash
python3 --version
```

---

## Instalação

```bash
# Clone o repositório
git clone https://github.com/raquer-raqueia/credscan
cd credscan

# Dê permissão de execução
chmod +x credscan.py
```

---

## Estrutura esperada de arquivos

```shell
credscan/
├── credscan.py          # Script principal
├── blacklist.txt        # Credenciais já reportadas (um email:senha por linha)
└── leaks/               # Exemplo de diretório com os dumps
├── dump_001.txt
├── dump_002.txt
└── ...
```

### Formato do `blacklist.txt`

Cada linha deve conter um par `email:senha` já reportado. Linhas iniciadas com `#` são tratadas como comentários e ignoradas.

> **Importante:** após cada ciclo de reporte, adicione os novos achados à `blacklist.txt` para evitar duplicidade futura.

---

## Como usar

### Modo com argumento (recomendado)

Execute o script com argumentos (pipelines e automação).

```bash
python3 credscan.py -d /caminho/para/leaks -b /caminho/para/blacklist.txt -o resultado.txt
```

---

## Parâmetros disponíveis

| Parâmetro | Forma curta | Descrição | Padrão |
|-----------|-------------|-----------|--------|
| `--directory` | `-d` | Caminho do diretório com os arquivos `.txt` | *(solicitado interativamente)* |
| `--blacklist` | `-b` | Caminho para o arquivo `blacklist.txt` | `./blacklist.txt` |
| `--output` | `-o` | Nome do arquivo de saída com os novos achados | `credscan_novos_<timestamp>.txt` |

---

## Entendendo os resultados

Durante a execução, o terminal exibe uma barra de progresso em tempo real:

⠹ [████████████░░░░░░░░░░░░░░░░░░]  40.0% │ Arqs:    40/100 │ Novos: 12 │ BL: 3 │ ⏱ 00:02:15  dump_042.txt

| Elemento | Descrição |
|----------|-----------|
| Barra de progresso | Percentual de arquivos processados |
| `Arqs` | Arquivos concluídos / total |
| `Novos` | Achados **não** presentes na blacklist |
| `BL` | Achados já presentes na blacklist (já reportados) |
| ⏱ | Tempo decorrido desde o início |
| Nome do arquivo | Último arquivo processado |



#### Ao finalizar, o relatório é exibido com as seguintes seções:

<img width="674" height="500" alt="image" src="https://github.com/user-attachments/assets/22574fc1-98fe-4d85-a96c-850811feaf02" />

<img width="752" height="475" alt="image" src="https://github.com/user-attachments/assets/86271627-75ff-4ada-8f6f-d273b7041394" />

---

## Como adicionar ou remover domínios

Abra o arquivo `credscan.py` e localize a lista `TARGET_DOMAINS`:

```python
TARGET_DOMAINS = [
    "@domain.gov.br",
    "@domain.gov.br",
    # adicione ou remova domínios aqui
]
```

Salve o arquivo. Nenhuma outra alteração é necessária.

---

## Aviso legal

> Esta ferramenta foi desenvolvida **exclusivamente para uso ético e responsável** por profissionais de segurança da informação, no contexto de atividades legítimas de **Threat Intelligence**, **SOC** e **reporte responsável de vazamentos** (*responsible disclosure*) aos clientes afetados.
>
> O uso desta ferramenta pressupõe autorização prévia dos titulares dos dados e das organizações envolvidas. O autor não se responsabiliza por uso indevido, ilegal ou fora do escopo descrito acima.
