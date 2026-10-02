import json
import logging
import os

import requests
from dotenv import load_dotenv

from IA.prompt import INSTRUCOES, montar_prompt

logger = logging.getLogger("risklayer.ollama")

DIR_IA = os.path.dirname(os.path.abspath(__file__))
DIR_RAIZ = os.path.dirname(DIR_IA)
load_dotenv(dotenv_path=os.path.join(DIR_RAIZ, ".env"))


def _host() -> str:
    # No Docker Compose, use o nome do serviço: http://ollama:11434
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434").strip().rstrip("/")
    if not host.startswith(("http://", "https://")):
        host = f"http://{host}"
    return host


def analisar_vulnerabilidade_ollama(vuln: dict, contexto: dict) -> dict:
    """Analisa o achado no Llama 3 local. Retorna {'impacto','recomendacao'} ou {'erro': ...}."""
    modelo = os.getenv("OLLAMA_MODEL", "llama3")
    payload = {
        "model": modelo,
        "system": INSTRUCOES,
        "prompt": montar_prompt(vuln, contexto),
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.0,
            "num_predict": int(os.getenv("OLLAMA_NUM_PREDICT", "768")),
        },
    }
    timeout = (5, int(os.getenv("OLLAMA_READ_TIMEOUT", "90")))  # (conexão, leitura)

    try:
        resp = requests.post(f"{_host()}/api/generate", json=payload, timeout=timeout)
        resp.raise_for_status()
        corpo = resp.json()
        if corpo.get("done_reason") == "length":
            return {"erro": "Resposta do Ollama truncada (aumente OLLAMA_NUM_PREDICT)."}
        return json.loads(corpo.get("response", ""))
    except json.JSONDecodeError:
        return {"erro": "Ollama não retornou um JSON válido."}
    except requests.exceptions.ConnectionError as e:
        logger.debug("Detalhe técnico da falha do Ollama", exc_info=e)
        return {"erro": "Ollama indisponível (serviço desligado ou inacessível)."}
    except requests.exceptions.Timeout as e:
        logger.debug("Detalhe técnico da falha do Ollama", exc_info=e)
        return {"erro": "Ollama não respondeu a tempo."}
    except requests.exceptions.HTTPError as e:
        logger.debug("Detalhe técnico da falha do Ollama", exc_info=e)
        codigo = e.response.status_code if e.response is not None else "?"
        return {"erro": f"Ollama retornou erro HTTP {codigo} (o modelo está instalado? ollama pull {modelo})."}
    except Exception as e:
        logger.debug("Detalhe técnico da falha do Ollama", exc_info=e)
        return {"erro": f"Falha ao consultar o Ollama ({type(e).__name__})."}