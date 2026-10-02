import json
import logging
import os
import sys

DIR_IA = os.path.dirname(os.path.abspath(__file__))
DIR_RAIZ = os.path.dirname(DIR_IA)
if DIR_RAIZ not in sys.path:  # permite rodar este arquivo direto (botão "Run Python File")
    sys.path.insert(0, DIR_RAIZ)

from pydantic import ValidationError  # noqa: E402

from IA.exportador import consolidar, gerar_pdf, nome_analise, salvar_json  # noqa: E402
from IA.gemini_service import analisar_vulnerabilidade_gemini  # noqa: E402
from IA.ollama_service import analisar_vulnerabilidade_ollama  # noqa: E402
from IA.rag_service import carregar_base_conhecimento, recuperar_contexto_relevante  # noqa: E402
from IA.schemas import AnaliseIA  # noqa: E402
from parser.parser_sarif import extrair_findings_sarif, ler_arquivo_sarif  # noqa: E402

logger = logging.getLogger("risklayer.analisador")

NIVEIS_NUVEM = {"HIGH", "CRITICAL"}
NOMES = {"gemini": "Gemini", "ollama": "Ollama (Llama 3)"}


def _nuvem_permitida() -> bool:
    """PERMITIR_NUVEM=0 força modo 100% local (nenhum dado vai para o Gemini)."""
    return os.getenv("PERMITIR_NUVEM", "1").strip().lower() not in {"0", "false", "nao", "não"}


def _validar(bruto, nome) -> dict:
    if not isinstance(bruto, dict):
        return {"erro": f"Resposta do {NOMES[nome]} não é um objeto JSON."}
    if "erro" in bruto:
        return bruto
    try:
        return AnaliseIA.model_validate(bruto).model_dump()
    except ValidationError as e:
        return {"erro": f"Resposta do {NOMES[nome]} fora do formato esperado ({e.error_count()} problema(s))."}


def _status_rag(contexto: dict) -> str:
    faltando = len(contexto["faltando"])
    if faltando == 0:
        return "completo"
    return "ausente" if faltando >= 3 else "parcial"


def analisar_vulnerabilidade_hibrida(vuln, owasp, cwe, remediacoes):
    """HIGH/CRITICAL: Gemini primeiro. MEDIUM/LOW/INFO: Llama local primeiro.
    O outro provedor é tentado UMA vez como fallback (salvo se a nuvem estiver desligada)."""
    sev = vuln.get("severity", "MEDIUM")
    contexto = recuperar_contexto_relevante(vuln, owasp, cwe, remediacoes)

    nuvem = ("gemini", analisar_vulnerabilidade_gemini)
    local = ("ollama", analisar_vulnerabilidade_ollama)
    ordem = [nuvem, local] if sev in NIVEIS_NUVEM else [local, nuvem]
    if not _nuvem_permitida():
        ordem = [local]

    falhas = []
    for i, (nome, analisar) in enumerate(ordem):
        logger.info("[%s] analisando %s (%s)", nome.upper(), vuln.get("id"), sev)
        resultado = _validar(analisar(vuln, contexto), nome)
        if "erro" not in resultado:
            return {
                **resultado,
                "risco": sev,  # decidido pelo código, nunca pelo modelo
                "modelo": nome,
                "contexto_rag": _status_rag(contexto),
                "status": "ok",
            }

        falhas.append(resultado["erro"])
        if i + 1 < len(ordem):
            logger.warning("%s A análise será feita via %s.", resultado["erro"], NOMES[ordem[i + 1][0]])
        else:
            logger.error("%s Não há outro provedor disponível para %s.", resultado["erro"], vuln.get("id"))

    return {
        "risco": sev,
        "modelo": None,
        "contexto_rag": _status_rag(contexto),
        "status": "erro",
        "erro": " | ".join(falhas),
    }


def analisar_findings(findings, owasp, cwe, remediacoes):
    """Analisa todos os achados, reaproveitando a análise de achados equivalentes
    (mesma regra, CWE, severidade, mensagem e arquivo) para reduzir custo e latência."""
    cache, analises = {}, []
    for f in findings:
        arquivo = str(f.get("location", "")).rsplit(":", 1)[0]
        chave = (
            f.get("rule_id"), f.get("cwe"), f.get("type"),
            f.get("severity"), f.get("description"), arquivo,
        )
        if chave not in cache:
            cache[chave] = analisar_vulnerabilidade_hibrida(f, owasp, cwe, remediacoes)
        analises.append(dict(cache[chave]))
    return analises


def main():
    """Uso: python -m IA.analisador [caminho_do_sarif]   (ou o botão Run do VS Code)"""
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(levelname)s %(name)s: %(message)s",
    )
    # Silencia o ruído das bibliotecas (continua visível com LOG_LEVEL=DEBUG)
    if os.getenv("LOG_LEVEL", "INFO").upper() != "DEBUG":
        for lib in ("httpx", "google_genai"):
            logging.getLogger(lib).setLevel(logging.WARNING)

    caminho = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join(DIR_RAIZ, "parser", "exemplo_semgrep.sarif")
    )
    owasp, cwe, remediacoes = carregar_base_conhecimento()
    findings = extrair_findings_sarif(ler_arquivo_sarif(caminho))
    print(f"--- RISKLAYER ASPM: ANALISANDO SARIF ({len(findings)} FINDINGS) ---")

    analises = analisar_findings(findings, owasp, cwe, remediacoes)
    achados = consolidar(findings, analises)
    print(json.dumps(achados, indent=2, ensure_ascii=False))
    nome = nome_analise(caminho)  # ex.: 20261001-143205_exemplo_semgrep
    print(f"\nJSON: {salvar_json(nome, achados)}")
    print(f"PDF:  {gerar_pdf(nome, achados)}")


if __name__ == "__main__":
    main()