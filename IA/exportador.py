# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, NOME 1, NOME 2, NOME 3
# RiskLayer ASPM - distribuído sob a licença BSD de 3 cláusulas (veja LICENSE.md).

import json
import os
import re
import glob
from collections import Counter
from datetime import datetime, timezone

from fpdf import FPDF
from fpdf.enums import XPos, YPos

DIR_IA = os.path.dirname(os.path.abspath(__file__))
DIR_RAIZ = os.path.dirname(DIR_IA)
DIR_RESULTADOS = os.path.join(DIR_RAIZ, "resultados")

ORDEM_SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
NEXT_LINE = {"new_x": XPos.LMARGIN, "new_y": YPos.NEXT}

# Substituições para caracteres comuns em texto de LLM que não existem em Latin-1
_SUBST = {
    "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
    "\u2013": "-", "\u2014": "-", "\u2022": "-", "\u2192": "->", "\u2026": "...",
}
_RE_NOME = re.compile(r"[A-Za-z0-9_-](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9_-])?")
_RE_ID = re.compile(r"[0-9a-f]{32}")


def pdf_texto(valor) -> str:
    """Torna qualquer texto seguro para as fontes core (Latin-1) do FPDF."""
    texto = "" if valor is None else str(valor)
    for origem, destino in _SUBST.items():
        texto = texto.replace(origem, destino)
    return texto.encode("latin-1", "replace").decode("latin-1")


def consolidar(findings, analises):
    """Junta achado + análise uma única vez e ordena por severidade (mais grave primeiro)."""
    achados = [{**f, "analise_ia": a} for f, a in zip(findings, analises)]
    return sorted(achados, key=lambda x: ORDEM_SEV.get(x.get("severity"), 9))


def nome_analise(origem=None) -> str:
    """Nome legível de pasta, ex.: 20261001-143205_exemplo_semgrep"""
    base = os.path.splitext(os.path.basename(origem or ""))[0]
    base = re.sub(r"[^A-Za-z0-9._-]+", "-", base).strip("-._")[:40]
    carimbo = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{carimbo}_{base}" if base else carimbo


def _dir_analise(nome: str) -> str:
    if not nome or not _RE_NOME.fullmatch(str(nome)):
        raise ValueError("nome de análise inválido")
    pasta = os.path.join(DIR_RESULTADOS, nome)
    os.makedirs(pasta, exist_ok=True)
    return pasta

def localizar_dir_analise(analise_id: str):
    """Acha resultados/<nome>_<id8> e confere o ID completo gravado no JSON.
    Retorna o caminho da pasta ou None. O UUID inteiro continua sendo a 'senha' do download."""
    if not _RE_ID.fullmatch(str(analise_id)):
        return None
    for pasta in glob.glob(os.path.join(DIR_RESULTADOS, f"*_{analise_id[:8]}")):
        try:
            with open(os.path.join(pasta, "relatorio_final.json"), encoding="utf-8") as f:
                if json.load(f).get("analise_id") == analise_id:
                    return pasta
        except (OSError, ValueError):
            continue
    return None


def salvar_json(nome: str, achados: list, analise_id: str | None = None) -> str:
    caminho = os.path.join(_dir_analise(nome), "relatorio_final.json")
    relatorio = {
        "analise_id": analise_id or nome,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_achados": len(achados),
        "resumo_severidade": dict(Counter(a.get("severity") for a in achados)),
        "achados": achados,
    }
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(relatorio, f, indent=2, ensure_ascii=False)
    return caminho

class PDFRelatorio(FPDF):
    def header(self):
        self.set_fill_color(15, 23, 42)
        self.rect(0, 0, 210, 22, "F")
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(255, 255, 255)
        self.set_xy(10, 5)
        self.cell(0, 6, pdf_texto("RiskLayer ASPM - Relatório de Análise de Segurança"), **NEXT_LINE)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(148, 163, 184)
        self.set_x(10)
        self.cell(0, 4, pdf_texto("Módulo de IA Híbrida (Llama 3 + Gemini)"), **NEXT_LINE)
        self.ln(8)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        self.cell(
            0, 10,
            pdf_texto(f"Gerado automaticamente pelo RiskLayer ASPM | Página {self.page_no()}"),
            align="C",
        )


def _campo(pdf, rotulo, valor):
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(28, 5, pdf_texto(rotulo), new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_font("Helvetica", "", 8)
    pdf.multi_cell(0, 5, pdf_texto(valor) or "-", **NEXT_LINE)


def _bloco(pdf, titulo, texto, cor_titulo):
    pdf.ln(1)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*cor_titulo)
    pdf.cell(0, 5, pdf_texto(titulo), **NEXT_LINE)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(30, 41, 59)
    pdf.multi_cell(0, 4, pdf_texto(texto) or "-", **NEXT_LINE)


def gerar_pdf(analise_id: str, achados: list) -> str:
    caminho_pdf = os.path.join(_dir_analise(analise_id), "relatorio_seguranca.pdf")

    pdf = PDFRelatorio()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    agora = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
    resumo = Counter(str(a.get("severity", "MEDIUM")).upper() for a in achados)
    resumo_txt = " | ".join(f"{s}: {resumo[s]}" for s in ORDEM_SEV if resumo.get(s))

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 6, pdf_texto(f"Data: {agora} | Total de vulnerabilidades: {len(achados)}"), **NEXT_LINE)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(0, 5, pdf_texto(f"Resumo por severidade: {resumo_txt or 'nenhum achado'}"), **NEXT_LINE)
    pdf.ln(2)

    for a in achados:
        analise = a.get("analise_ia") or {}
        sev = str(a.get("severity", "MEDIUM")).upper()

        if pdf.get_y() > 235:  # evita título de achado isolado no fim da página
            pdf.add_page()

        if sev in ("HIGH", "CRITICAL"):
            pdf.set_fill_color(220, 38, 38)
        elif sev == "MEDIUM":
            pdf.set_fill_color(217, 119, 6)
        else:
            pdf.set_fill_color(37, 99, 235)

        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        titulo = f" [{sev}] {a.get('id')} - {str(a.get('rule_id'))[:110]}"
        pdf.cell(0, 6, pdf_texto(titulo), fill=True, **NEXT_LINE)

        pdf.set_text_color(30, 41, 59)
        pdf.ln(2)
        _campo(pdf, "Scanner:", a.get("scanner"))
        _campo(pdf, "Local:", a.get("location"))
        _campo(pdf, "Categoria:", f"{a.get('type')} | {a.get('cwe') or 'CWE n/d'}")
        _campo(pdf, "Descrição:", a.get("description"))
        _campo(
            pdf, "Análise IA:",
            f"modelo {analise.get('modelo') or 'n/d'} | contexto RAG {analise.get('contexto_rag', 'n/d')}",
        )

        if analise.get("status") == "erro":
            _bloco(pdf, "Análise de IA indisponível:", analise.get("erro"), (153, 27, 27))
        else:
            _bloco(pdf, "Análise de Impacto (Diagnóstico IA):", analise.get("impacto"), (153, 27, 27))
            _bloco(pdf, "Recomendação de Remediação (Orientação IA):", analise.get("recomendacao"), (22, 101, 52))

        pdf.ln(4)

    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 116, 139)
    pdf.multi_cell(
        0, 4,
        pdf_texto("Aviso: análises e recomendações geradas por IA. Valide-as antes de aplicar correções."),
        **NEXT_LINE,
    )

    pdf.output(caminho_pdf)
    return caminho_pdf