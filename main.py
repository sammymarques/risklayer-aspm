# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, Samuel de Oliveira Marques, Vladmir Aleiksander Pugliesi Vilasboas di Araujo
# RiskLayer ASPM - distribuído sob a licença BSD de 3 cláusulas (veja LICENSE.md).

import json
import logging
import os
import secrets
from collections import Counter
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from IA import exportador
from IA.analisador import analisar_findings
from IA.rag_service import carregar_base_conhecimento
from parser.parser_sarif import extrair_findings_sarif

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("risklayer")

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_FINDINGS = int(os.getenv("MAX_FINDINGS", "100"))

DIR_RAIZ = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(
    title="RiskLayer ASPM - Módulo de IA Híbrida",
    description="API REST para triagem inteligente de vulnerabilidades (SARIF) utilizando Llama 3 local e Gemini Cloud.",
    version="1.1.0",
)

# A API não usa cookies: sem credenciais. Em produção, liste as origens do front em CORS_ORIGINS.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Falha cedo (na subida) se alguma base de conhecimento estiver ausente ou quebrada
owasp, cwe, remediacoes = carregar_base_conhecimento()


def verificar_api_key(x_api_key: str | None = Header(default=None)):
    """Se RISKLAYER_API_KEY estiver definida, exige o header X-API-Key."""
    esperada = os.getenv("RISKLAYER_API_KEY")
    if esperada and not secrets.compare_digest((x_api_key or "").encode(), esperada.encode()):
        raise HTTPException(status_code=401, detail="API key inválida ou ausente")


@app.get("/")
def home():
    """Health check."""
    return {"servico": "RiskLayer ASPM - AI Engine", "status": "operacional", "versao": "1.1.0"}


@app.get("/app", include_in_schema=False)
def servir_frontend():
    """Serve a interface (static/index.html), independente da pasta de onde o servidor foi iniciado."""
    caminho = os.path.join(DIR_RAIZ, "static", "index.html")
    if not os.path.exists(caminho):
        raise HTTPException(status_code=404, detail="Interface não encontrada: crie static/index.html")
    return FileResponse(caminho, media_type="text/html")


@app.post("/api/v1/analisar-sarif", dependencies=[Depends(verificar_api_key)])
def analisar_sarif_endpoint(file: UploadFile = File(...)):
    """Recebe um SARIF, executa a análise híbrida com RAG e devolve os achados analisados."""
    conteudo = file.file.read(MAX_UPLOAD_BYTES + 1)
    if len(conteudo) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Arquivo excede o limite de 5 MB")

    try:
        findings = extrair_findings_sarif(json.loads(conteudo))
    except ValueError:
        raise HTTPException(status_code=422, detail="O arquivo enviado não é um SARIF válido")

    if not findings:
        return {
            "mensagem": "Nenhuma vulnerabilidade encontrada no arquivo SARIF.",
            "total_achados": 0,
            "achados": [],
            "download_pdf_url": None,
        }
    if len(findings) > MAX_FINDINGS:
        raise HTTPException(
            status_code=413,
            detail=f"O SARIF tem {len(findings)} achados; o limite é {MAX_FINDINGS}",
        )

    try:
        analises = analisar_findings(findings, owasp, cwe, remediacoes)
        achados = exportador.consolidar(findings, analises)

        analise_id = uuid4().hex
        nome = f"{exportador.nome_analise(file.filename)}_{analise_id[:8]}"
        exportador.salvar_json(nome, achados, analise_id=analise_id)

        try:
            exportador.gerar_pdf(nome, achados)
            pdf_ok = True
        except Exception:
            logger.exception("Falha ao gerar o PDF da análise %s", analise_id)
            pdf_ok = False
    except Exception:
        logger.exception("Erro inesperado ao processar o SARIF")
        raise HTTPException(status_code=500, detail="Erro interno ao processar a análise")

    return {
        "analise_id": analise_id,
        "arquivo_processado": file.filename,
        "total_achados": len(achados),
        "resumo_severidade": dict(Counter(a.get("severity") for a in achados)),
        "analises_com_erro": sum(
            1 for a in achados if (a.get("analise_ia") or {}).get("status") == "erro"
        ),
        "achados": achados,
        "download_pdf_url": f"/api/v1/relatorio-pdf/{analise_id}" if pdf_ok else None,
    }


@app.get("/api/v1/relatorio-pdf/{analise_id}", dependencies=[Depends(verificar_api_key)])
def download_pdf(analise_id: UUID):
    pasta = exportador.localizar_dir_analise(analise_id.hex)
    caminho = os.path.join(pasta, "relatorio_seguranca.pdf") if pasta else None
    if not caminho or not os.path.exists(caminho):
        raise HTTPException(status_code=404, detail="Relatório não encontrado.")
    return FileResponse(
        path=caminho,
        filename="RiskLayer_Relatorio_Seguranca.pdf",
        media_type="application/pdf",
    )