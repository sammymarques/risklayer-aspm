# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, NOME 1, NOME 2, NOME 3
# RiskLayer ASPM - distribuído sob a licença BSD de 3 cláusulas (veja LICENSE.md).

"""Normalização de severidade e mapeamento CWE -> OWASP Top 10 2025."""
import re

NAO_CLASSIFICADO = "NAO-CLASSIFICADO"
_RE_CWE = re.compile(r"CWE-(\d+)", re.IGNORECASE)

CWE_PARA_OWASP = {
    79: "A05:2025-Injection",
    89: "A05:2025-Injection",
    200: "A01:2025-Broken Access Control",
    209: "A10:2025-Mishandling of Exceptional Conditions",
    284: "A01:2025-Broken Access Control",
    798: "A07:2025-Authentication Failures",
    918: "A01:2025-Broken Access Control",
    1004: "A02:2025-Security Misconfiguration",
    1395: "A03:2025-Software Supply Chain Failures",
}


def extrair_cwe_id(texto) -> str:
    """'CWE-89: ...' ou 'external/cwe/cwe-089' -> 'CWE-89'. Retorna '' se não houver."""
    m = _RE_CWE.search(str(texto or ""))
    return f"CWE-{int(m.group(1))}" if m else ""


def mapear_cwe_para_owasp(cwe) -> str:
    """Mapeia um CWE (texto livre ou ID) para a categoria OWASP Top 10 2025."""
    cwe_id = extrair_cwe_id(cwe)
    if not cwe_id:
        return NAO_CLASSIFICADO
    return CWE_PARA_OWASP.get(int(cwe_id.split("-")[1]), NAO_CLASSIFICADO)


def converter_severidade_sarif(level, security_severity=None) -> str:
    """Converte level do SARIF (ou a nota 'security-severity' 0-10) para a severidade da ASPM."""
    try:
        nota = float(security_severity)
    except (TypeError, ValueError):
        nota = None
    if nota is not None:
        if nota >= 9.0:
            return "CRITICAL"
        if nota >= 7.0:
            return "HIGH"
        if nota >= 4.0:
            return "MEDIUM"
        return "LOW"

    nivel = "warning" if level is None else str(level).lower()  # padrão do SARIF
    mapa = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}
    return mapa.get(nivel, "MEDIUM")