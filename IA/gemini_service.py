# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, Samuel de Oliveira Marques, Vladmir Aleiksander Pugliesi Vilasboas di Araujo
# RiskLayer ASPM - distribuído sob a licença BSD de 3 cláusulas (veja LICENSE.md).

import json
import logging
import os
import time

from dotenv import load_dotenv
from google import genai
from google.genai import errors as genai_errors
from google.genai import types

from IA.prompt import INSTRUCOES, montar_prompt
from IA.schemas import AnaliseIA

logger = logging.getLogger("risklayer.gemini")

DIR_IA = os.path.dirname(os.path.abspath(__file__))
DIR_RAIZ = os.path.dirname(DIR_IA)
load_dotenv(dotenv_path=os.path.join(DIR_RAIZ, ".env"))

_client = None


class GeminiNaoConfigurado(Exception):
    pass


def _get_client():
    """Cliente criado sob demanda: sem chave, só o Gemini falha (o modo local continua)."""
    global _client
    if _client is None:
        chave = os.getenv("GEMINI_API_KEY")
        if not chave:
            raise GeminiNaoConfigurado("GEMINI_API_KEY não configurada")
        timeout_ms = int(os.getenv("GEMINI_TIMEOUT_MS", "45000"))  # em milissegundos
        _client = genai.Client(
            api_key=chave, http_options=types.HttpOptions(timeout=timeout_ms)
        )
    return _client


def _erro_amigavel(e: Exception) -> str:
    """Traduz exceções do Gemini em mensagens curtas em português.
    O detalhe técnico completo só aparece com LOG_LEVEL=DEBUG."""
    logger.debug("Detalhe técnico da falha do Gemini", exc_info=e)

    if isinstance(e, GeminiNaoConfigurado):
        return "Gemini não configurado (GEMINI_API_KEY ausente)."

    if isinstance(e, genai_errors.APIError):
        codigo = getattr(e, "code", None)
        if codigo == 503:
            return "Gemini indisponível no momento devido ao tráfego intenso."
        if codigo == 429:
            return "Limite de requisições do Gemini atingido no momento."
        if codigo in (401, 403):
            return "Gemini recusou a chave de API (verifique GEMINI_API_KEY)."
        if codigo == 404:
            return "Modelo do Gemini não encontrado (verifique GEMINI_MODEL)."
        if isinstance(codigo, int) and codigo >= 500:
            return "Gemini com erro temporário nos servidores do Google."
        return f"Gemini retornou um erro (código {codigo})."

    if isinstance(e, ValueError):  # inclui JSONDecodeError
        return "Gemini retornou uma resposta que não é um JSON válido."

    nome = type(e).__name__
    if "timeout" in nome.lower():
        return "Gemini não respondeu a tempo."
    return f"Falha ao consultar o Gemini ({nome})."


def analisar_vulnerabilidade_gemini(vuln: dict, contexto: dict) -> dict:
    """Analisa o achado no Gemini. Retorna {'impacto','recomendacao'} ou {'erro': ...}.
    Em 503 (pico de demanda) tenta de novo com espera curta antes de desistir."""
    tentativas = int(os.getenv("GEMINI_RETRIES", "2"))
    prompt = montar_prompt(vuln, contexto)
    try:
        for i in range(tentativas + 1):
            try:
                response = _get_client().models.generate_content(
                    model=os.getenv("GEMINI_MODEL", "gemini-3.6-flash"),
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=INSTRUCOES,
                        response_mime_type="application/json",
                        response_schema=AnaliseIA,
                        temperature=0.1,
                    ),
                )
                break
            except genai_errors.APIError as e:
                if getattr(e, "code", None) == 503 and i < tentativas:
                    espera = 2 * (i + 1)  # 2 s, depois 4 s
                    logger.info("Gemini com tráfego intenso. Nova tentativa em %ss...", espera)
                    time.sleep(espera)
                    continue
                raise
        if not response.text:
            return {"erro": "Gemini retornou resposta vazia (possível bloqueio de segurança)."}
        return json.loads(response.text)
    except Exception as e:
        return {"erro": _erro_amigavel(e)}