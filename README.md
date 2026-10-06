# RiskLayer ASPM — Módulo de IA

Plataforma acadêmica de **ASPM (Application Security Posture Management)**. Este repositório contém o **módulo de IA** (API REST em FastAPI) e uma interface web de demonstração.

A API recebe relatórios de vulnerabilidades no formato **SARIF**, normaliza severidade e categoria OWASP Top 10 2025, enriquece cada achado com uma base de conhecimento local (RAG: OWASP, CWE e remediações) e usa IA para gerar um diagnóstico de impacto e uma recomendação de correção em português. Também gera relatórios em JSON e PDF.

## Como funciona

1. **Ingestão:** `POST /api/v1/analisar-sarif` recebe o arquivo `.sarif`.
2. **Parser e normalização:** extrai os achados, converte a severidade e mapeia o CWE para o OWASP Top 10 2025.
3. **RAG:** busca contexto na pasta `conhecimento/` (`owasp.json`, `cwe.json`, `remediacoes.json`).
4. **IA híbrida:** achados HIGH/CRITICAL vão para o **Gemini** (nuvem); MEDIUM/LOW/INFO vão para o **Llama 3** local (Ollama). Se um provedor falhar (por exemplo, 503 por tráfego intenso), o outro assume automaticamente.
5. **Validação:** a resposta da IA é validada por schema e a severidade final vem do código, nunca do modelo.
6. **Exportação:** um relatório JSON e um PDF por análise, em `resultados/`.

**Privacidade:** o código-fonte nunca é enviado a nenhum modelo. Para a nuvem vão apenas metadados do achado (regra, CWE, categoria OWASP, severidade, arquivo:linha e mensagem do scanner). Com `PERMITIR_NUVEM=0` o sistema funciona 100% local.

## Requisitos

- Python 3.11 ou superior
- [Ollama](https://ollama.com) com o modelo `llama3` (`ollama pull llama3`)
- Chave de API do Gemini (Google AI Studio)

## Instalação

```bash
git clone https://github.com/sammymarques/risklayer-aspm.git
cd risklayer-aspm
python -m venv .venv
source .venv/Scripts/activate      # Git Bash no Windows (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt
cp .env.example .env               # depois edite o .env e preencha GEMINI_API_KEY
```

> O arquivo `.env` contém segredos e **nunca** deve ser commitado (já está no `.gitignore`).

## Configuração (`.env`)

| Variável | Descrição | Padrão |
|---|---|---|
| `GEMINI_API_KEY` | Chave da API do Gemini | (obrigatória para usar a nuvem) |
| `GEMINI_MODEL` | Modelo do Gemini | `gemini-3.6-flash` |
| `OLLAMA_HOST` | Endereço do Ollama | `http://localhost:11434` |
| `OLLAMA_MODEL` | Modelo local | `llama3` |
| `PERMITIR_NUVEM` | `0` desliga o Gemini (modo 100% local) | `1` |
| `MAX_FINDINGS` | Máximo de achados por upload | `100` |
| `RISKLAYER_API_KEY` | Se definida, exige o header `X-API-Key` | (desativada) |
| `CORS_ORIGINS` | Origens permitidas, separadas por vírgula | `*` |
| `LOG_LEVEL` | `INFO` ou `DEBUG` | `INFO` |

## Usando a interface web

1. Deixe o **Ollama** rodando (abra o aplicativo ou rode `ollama serve`) e confirme que o `.env` tem a `GEMINI_API_KEY`.
2. Inicie o servidor na raiz do projeto:

```bash
   python -m uvicorn main:app --port 8000
```

3. Abra no navegador: **http://127.0.0.1:8000/app**
4. Clique na área de upload (ou arraste o arquivo) e selecione um SARIF. Há um exemplo pronto em `parser/exemplo_demo.sarif`.
5. Clique em **Iniciar Análise**. A IA analisa cada achado em sequência, então pode levar de alguns segundos a alguns minutos.
6. Veja o resumo por severidade e os achados com impacto e recomendação, e use **Baixar Relatório PDF** para o relatório completo.

Documentação interativa da API (Swagger): http://127.0.0.1:8000/docs

## Como executar

```bash
# API + interface web
python -m uvicorn main:app --port 8000
#   Interface:  http://127.0.0.1:8000/app
#   Swagger:    http://127.0.0.1:8000/docs

# Linha de comando (grava em resultados/<data>_<arquivo>/)
python -m IA.analisador parser/exemplo_demo.sarif
```

Exemplo com `curl`:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/analisar-sarif -F "file=@parser/exemplo_demo.sarif"
```

### Rotas

| Método | Rota | Descrição |
|---|---|---|
| GET | `/` | Health check |
| GET | `/app` | Interface web |
| POST | `/api/v1/analisar-sarif` | Analisa um SARIF (campo `file`) e devolve os achados com a análise da IA |
| GET | `/api/v1/relatorio-pdf/{analise_id}` | Baixa o PDF da análise |

Erros: `413` (arquivo maior que 5 MB ou com mais de `MAX_FINDINGS` achados), `422` (arquivo não é um SARIF válido), `401` (somente se `RISKLAYER_API_KEY` estiver definida).

## Docker (opcional)

```bash
docker build -t risklayer .
docker run --rm -p 8000:8000 --env-file .env -e OLLAMA_HOST=http://host.docker.internal:11434 risklayer
```

## Testes

```bash
python -m pytest -q
```

Os testes usam provedores de IA simulados (não consomem a cota do Gemini) e cobrem o parser, o roteamento híbrido com fallback, os exportadores e a API.

## Estrutura

```
main.py            API FastAPI e rotas
static/index.html  interface web
parser/            leitura do SARIF e normalização
IA/                roteamento híbrido, serviços Gemini/Ollama, RAG, prompts, exportação
conhecimento/      base de conhecimento (OWASP, CWE, remediações)
resultados/        relatórios gerados (ignorado pelo Git)
tests/             testes automatizados
```

## Licença

Distribuído sob a licença **BSD 3-Clause**. Veja o arquivo [LICENSE.md](LICENSE.md).

## Créditos e atribuições

- Categorias do **OWASP Top 10:2025** (OWASP Foundation) e nomes de **CWE™** (MITRE) usados na base de conhecimento.
- **SARIF** é um padrão do OASIS.
- Bibliotecas de terceiros (FastAPI, Pydantic, Uvicorn, FPDF2, google-genai, Requests, python-dotenv e outras) são instaladas via `pip`, cada uma sob a sua própria licença. A interface carrega Tailwind CSS e Font Awesome por CDN.


## Autores

| Nome | Responsabilidade | GitHub |
|---|---|---|

| Samuel de Oliveira Marques | Módulo de IA (API, parser SARIF, RAG, IA híbrida, relatórios) e interface de demonstração | [@SEU_USUARIO](https://github.com/sammymarques) |

| Vladmir Aleiksander Pugliesi Vilasboas di Araujo | Front-end original em React | [@bytedump](https://github.com/bytedump) |