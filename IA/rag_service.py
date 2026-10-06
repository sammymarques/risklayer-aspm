# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, NOME 1, NOME 2, NOME 3
# RiskLayer ASPM - distribuído sob a licença BSD de 3 cláusulas (veja LICENSE.md).

import json
import os
from functools import lru_cache

DIR_IA = os.path.dirname(os.path.abspath(__file__))
DIR_RAIZ = os.path.dirname(DIR_IA)
DIR_CONHECIMENTO = os.path.join(DIR_RAIZ, "conhecimento")


@lru_cache(maxsize=1)
def carregar_base_conhecimento():
    """Lê (uma única vez) OWASP, CWE e remediações. Falha alto se faltar arquivo ou JSON quebrado."""
    bases = []
    for nome in ("owasp", "cwe", "remediacoes"):
        caminho = os.path.join(DIR_CONHECIMENTO, f"{nome}.json")
        with open(caminho, "r", encoding="utf-8") as f:
            dados = json.load(f)
        if not isinstance(dados, dict) or not dados:
            raise ValueError(f"Base de conhecimento vazia ou inválida: {caminho}")
        bases.append(dados)
    return tuple(bases)  # (owasp, cwe, remediacoes)


def recuperar_contexto_relevante(finding, owasp_db, cwe_db, remediacoes_db):
    """Monta o contexto RAG do achado. Itens não encontrados ficam como None e em 'faltando'."""
    tipo = finding.get("type", "")
    cwe_id = finding.get("cwe", "")
    rule_id = finding.get("rule_id", "")

    info_cwe = cwe_db.get(cwe_id)
    contexto = {
        "owasp": owasp_db.get(tipo),
        "cwe": (
            f"{cwe_id} - {info_cwe.get('nome', '')}: {info_cwe.get('descricao', '')}"
            if isinstance(info_cwe, dict)
            else None
        ),
        "remediacao": (
            remediacoes_db.get(rule_id)
            or remediacoes_db.get(cwe_id)
            or remediacoes_db.get(tipo)
        ),
    }
    contexto["faltando"] = [chave for chave, valor in contexto.items() if valor is None]
    return contexto