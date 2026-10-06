"""Adiciona o cabeçalho de licença (SPDX) aos arquivos-fonte.
Uso (na raiz do projeto): python aplicar_licenca.py"""
import os
import re

ANO = "2026"
AUTORES = "Samuel de Oliveira Marques, Vladmir Aleiksander Pugliesi Vilasboas di Araujo"  # <-- EDITE: todos os integrantes do grupo
IGNORAR = {".git", "__pycache__", ".venv", "venv", ".pytest_cache", "resultados", "node_modules"}

LINHAS = [
    "SPDX-License-Identifier: BSD-3-Clause",
    f"Copyright (c) {ANO}, {AUTORES}",
    "RiskLayer ASPM - distribuído sob a licença BSD de 3 cláusulas (veja LICENSE.md).",
]
EXT_HASH = {".py"}
NOMES_HASH = {"Dockerfile", "requirements.txt"}


def montar(eol, html):
    if html:
        return "<!--" + eol + eol.join("  " + l for l in LINHAS) + eol + "-->" + eol
    return eol.join("# " + l for l in LINHAS) + eol


def processar(caminho, html):
    with open(caminho, "r", encoding="utf-8", newline="") as f:
        texto = f.read()
    if "SPDX-License-Identifier" in texto:
        return False
    eol = "\r\n" if "\r\n" in texto else "\n"
    cab = montar(eol, html)
    if html:
        m = re.match(r"\s*<!doctype[^>]*>[ \t]*\r?\n", texto, re.IGNORECASE)
        pos = m.end() if m else 0
        novo = texto[:pos] + cab + texto[pos:]
    else:
        linhas = texto.splitlines(keepends=True)
        topo = linhas[0] if linhas and linhas[0].startswith("#!") else ""
        novo = topo + cab + eol + texto[len(topo):]
    with open(caminho, "w", encoding="utf-8", newline="") as f:
        f.write(novo)
    return True


total = 0
for raiz, dirs, arquivos in os.walk("."):
    dirs[:] = [d for d in dirs if d not in IGNORAR]
    for nome in arquivos:
        caminho = os.path.join(raiz, nome)
        if os.path.abspath(caminho) == os.path.abspath(__file__):
            continue
        ext = os.path.splitext(nome)[1].lower()
        if ext == ".html" or ext in EXT_HASH or nome in NOMES_HASH:
            if processar(caminho, html=(ext == ".html")):
                total += 1
                print("cabeçalho adicionado:", caminho)
print(f"{total} arquivo(s) atualizado(s).")