import json
import os
import sys

_RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _RAIZ not in sys.path:
    sys.path.insert(0, _RAIZ)

from parser.normalizador import (
    converter_severidade_sarif,
    extrair_cwe_id,
    mapear_cwe_para_owasp,
)


def ler_arquivo_sarif(caminho_sarif):
    """Carrega o SARIF. Erros sobem para quem chamou (nada de 'zero achados' silencioso)."""
    with open(caminho_sarif, "r", encoding="utf-8") as f:
        return json.load(f)


def _cwe_da_regra(regra):
    """Procura o CWE em properties.cwe (texto ou lista) e em properties.tags."""
    props = regra.get("properties") or {}
    cwe = props.get("cwe") or []
    candidatos = [cwe] if isinstance(cwe, str) else list(cwe)
    candidatos += list(props.get("tags") or [])
    for candidato in candidatos:
        cwe_id = extrair_cwe_id(candidato)
        if cwe_id:
            return cwe_id
    return ""


def _extrair(runs):
    findings, contador = [], 0  # contador único entre todos os runs

    for run in runs:
        driver = (run.get("tool") or {}).get("driver") or {}
        scanner = driver.get("name", "Scanner Desconhecido")

        regras = {}
        for regra in driver.get("rules") or []:
            regras[regra.get("id")] = {
                "cwe": _cwe_da_regra(regra),
                "nivel": (regra.get("defaultConfiguration") or {}).get("level"),
                "sec": (regra.get("properties") or {}).get("security-severity"),
            }

        for result in run.get("results") or []:
            contador += 1
            rule_id = result.get("ruleId", "Sem ID")
            info = regras.get(rule_id, {})
            nivel = result.get("level") or info.get("nivel") or "warning"
            cwe_id = info.get("cwe", "")

            arquivo, linha = "Localização não informada", 0
            locations = result.get("locations") or []
            if locations:
                fisica = locations[0].get("physicalLocation") or {}
                arquivo = (fisica.get("artifactLocation") or {}).get("uri", arquivo)
                linha = (fisica.get("region") or {}).get("startLine", linha)

            findings.append(
                {
                    "id": f"SARIF-{contador:03d}",
                    "scanner": scanner,
                    "rule_id": rule_id,
                    "cwe": cwe_id,
                    "type": mapear_cwe_para_owasp(cwe_id),
                    "source": scanner,
                    "severity": converter_severidade_sarif(nivel, info.get("sec")),
                    "location": f"{arquivo}:{linha}",
                    "description": (result.get("message") or {}).get(
                        "text", "Sem descrição disponível."
                    ),
                }
            )
    return findings


def extrair_findings_sarif(dados_sarif):
    """Extrai e normaliza os achados. Levanta ValueError se não for um SARIF válido."""
    if not isinstance(dados_sarif, dict) or not isinstance(dados_sarif.get("runs"), list):
        raise ValueError("Arquivo não parece ser um SARIF válido (campo 'runs' ausente)")
    try:
        return _extrair(dados_sarif["runs"])
    except (AttributeError, TypeError) as e:
        raise ValueError("Estrutura do SARIF inesperada") from e


if __name__ == "__main__":
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    CAMINHO_TESTE = os.path.join(BASE_DIR, "exemplo_semgrep.sarif")

    print("--- TESTANDO PARSER SARIF NORMALIZADO ---")
    achados = extrair_findings_sarif(ler_arquivo_sarif(CAMINHO_TESTE))
    print(f"\nFindings extraídos e normalizados ({len(achados)}):")
    print(json.dumps(achados, indent=2, ensure_ascii=False))