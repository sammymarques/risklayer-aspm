import json
import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from IA import analisador, exportador
from parser.normalizador import (
    NAO_CLASSIFICADO,
    converter_severidade_sarif,
    mapear_cwe_para_owasp,
)
from parser.parser_sarif import extrair_findings_sarif

OK = {
    "impacto": "Impacto de teste com tamanho suficiente.",
    "recomendacao": "Recomendação de teste com tamanho suficiente.",
}
ERRO = {"erro": "falhou"}
VULN = {
    "id": "SARIF-001", "scanner": "Semgrep", "rule_id": "r.sqli", "cwe": "CWE-89",
    "type": "A05:2025-Injection", "severity": "HIGH", "location": "a.py:1", "description": "d",
}


def _sarif(rule_id="r.sqli", cwe="CWE-89: SQL Injection", level="error"):
    resultado = {
        "ruleId": rule_id,
        "message": {"text": "mensagem"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "app/auth.py"}, "region": {"startLine": 45}}}],
    }
    if level:
        resultado["level"] = level
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Semgrep",
                            "rules": [{"id": rule_id, "properties": {"cwe": [cwe]}}]}},
        "results": [resultado],
    }]}


def _fakes(monkeypatch, gemini, ollama):
    chamadas = []

    def fabrica(nome, resposta):
        def _f(vuln, contexto):
            chamadas.append(nome)
            return dict(resposta)
        return _f

    monkeypatch.setattr(analisador, "analisar_vulnerabilidade_gemini", fabrica("gemini", gemini))
    monkeypatch.setattr(analisador, "analisar_vulnerabilidade_ollama", fabrica("ollama", ollama))
    return chamadas


# ---------- normalizador ----------
def test_cwe_798_nao_vira_injection():
    assert mapear_cwe_para_owasp("CWE-798: Use of Hard-coded Credentials") == "A07:2025-Authentication Failures"


def test_cwe_desconhecido_ou_vazio_nao_classificado():
    assert mapear_cwe_para_owasp("") == NAO_CLASSIFICADO
    assert mapear_cwe_para_owasp("CWE-99999") == NAO_CLASSIFICADO


def test_severidades():
    assert converter_severidade_sarif(None) == "MEDIUM"  # padrão do SARIF é warning
    assert converter_severidade_sarif("error") == "HIGH"
    assert converter_severidade_sarif("none") == "INFO"
    assert converter_severidade_sarif("warning", "9.8") == "CRITICAL"
    assert converter_severidade_sarif("warning", "7.5") == "HIGH"


# ---------- parser ----------
def test_parser_extrai_sqli():
    f = extrair_findings_sarif(_sarif())[0]
    assert (f["severity"], f["cwe"], f["type"]) == ("HIGH", "CWE-89", "A05:2025-Injection")
    assert f["location"] == "app/auth.py:45"


def test_parser_sem_level_vira_medium():
    assert extrair_findings_sarif(_sarif(level=None))[0]["severity"] == "MEDIUM"


def test_parser_cookie_cwe_1004_vira_a02():
    f = extrair_findings_sarif(_sarif("r.cookie", "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag", "warning"))[0]
    assert f["type"] == "A02:2025-Security Misconfiguration"


def test_parser_ids_unicos_entre_runs():
    dados = _sarif()
    dados["runs"].append(_sarif()["runs"][0])
    assert [f["id"] for f in extrair_findings_sarif(dados)] == ["SARIF-001", "SARIF-002"]


def test_parser_rejeita_sarif_invalido():
    with pytest.raises(ValueError):
        extrair_findings_sarif({"foo": 1})


# ---------- roteamento híbrido ----------
def test_high_usa_gemini_primeiro(monkeypatch):
    chamadas = _fakes(monkeypatch, OK, OK)
    r = analisador.analisar_vulnerabilidade_hibrida(dict(VULN), {}, {}, {})
    assert chamadas == ["gemini"] and r["modelo"] == "gemini" and r["status"] == "ok"


def test_high_gemini_falha_cai_no_ollama(monkeypatch):
    chamadas = _fakes(monkeypatch, ERRO, OK)
    r = analisador.analisar_vulnerabilidade_hibrida(dict(VULN), {}, {}, {})
    assert chamadas == ["gemini", "ollama"] and r["modelo"] == "ollama"


def test_ambos_falham_cada_provedor_e_chamado_uma_vez(monkeypatch):
    chamadas = _fakes(monkeypatch, ERRO, ERRO)
    r = analisador.analisar_vulnerabilidade_hibrida(dict(VULN), {}, {}, {})
    assert chamadas == ["gemini", "ollama"] and r["status"] == "erro"


def test_medium_usa_ollama_primeiro_e_cai_no_gemini(monkeypatch):
    chamadas = _fakes(monkeypatch, OK, ERRO)
    r = analisador.analisar_vulnerabilidade_hibrida({**VULN, "severity": "MEDIUM"}, {}, {}, {})
    assert chamadas == ["ollama", "gemini"] and r["modelo"] == "gemini"


def test_modo_local_only_nunca_chama_a_nuvem(monkeypatch):
    monkeypatch.setenv("PERMITIR_NUVEM", "0")
    chamadas = _fakes(monkeypatch, OK, OK)
    analisador.analisar_vulnerabilidade_hibrida(dict(VULN), {}, {}, {})
    assert chamadas == ["ollama"]


def test_modelo_nao_altera_o_risco(monkeypatch):
    _fakes(monkeypatch, {**OK, "risco": "LOW"}, OK)
    assert analisador.analisar_vulnerabilidade_hibrida(dict(VULN), {}, {}, {})["risco"] == "HIGH"


def test_resposta_fora_do_schema_aciona_fallback(monkeypatch):
    chamadas = _fakes(monkeypatch, {"impacto": "curto"}, OK)
    r = analisador.analisar_vulnerabilidade_hibrida(dict(VULN), {}, {}, {})
    assert chamadas == ["gemini", "ollama"] and r["modelo"] == "ollama"


def test_cache_reaproveita_achados_equivalentes(monkeypatch):
    chamadas = _fakes(monkeypatch, OK, OK)
    base = {**VULN, "severity": "MEDIUM"}
    findings = [
        {**base, "id": "1", "location": "a.py:1"},
        {**base, "id": "2", "location": "a.py:9"},
        {**base, "id": "3", "location": "b.py:2"},
    ]
    analises = analisador.analisar_findings(findings, {}, {}, {})
    assert len(analises) == 3 and len(chamadas) == 2


# ---------- exportador ----------
def test_pdf_texto_aceita_caracteres_fora_do_latin1():
    assert exportador.pdf_texto("“x” – y → z").encode("latin-1") == b'"x" - y -> z'


def test_consolidar_ordena_por_severidade():
    achados = exportador.consolidar(
        [{**VULN, "severity": "MEDIUM"}, {**VULN, "severity": "CRITICAL"}], [{}, {}]
    )
    assert [a["severity"] for a in achados] == ["CRITICAL", "MEDIUM"]


def test_exportadores_geram_arquivos_com_unicode_e_erro(monkeypatch, tmp_path):
    monkeypatch.setattr(exportador, "DIR_RESULTADOS", str(tmp_path))
    analise_ok = {**OK, "impacto": "Texto com “aspas” – travessão → seta •",
                  "risco": "HIGH", "modelo": "gemini", "contexto_rag": "parcial", "status": "ok"}
    analise_erro = {"risco": "MEDIUM", "modelo": None, "contexto_rag": "ausente",
                    "status": "erro", "erro": "gemini: falhou | ollama: falhou"}
    achados = exportador.consolidar(
        [VULN, {**VULN, "id": "SARIF-002", "severity": "MEDIUM"}], [analise_ok, analise_erro]
    )
    analise_id = uuid4().hex
    pdf = exportador.gerar_pdf(analise_id, achados)
    js = exportador.salvar_json(analise_id, achados)
    assert os.path.getsize(pdf) > 0
    assert json.load(open(js, encoding="utf-8"))["total_achados"] == 2


def test_exportador_rejeita_id_invalido(tmp_path, monkeypatch):
    monkeypatch.setattr(exportador, "DIR_RESULTADOS", str(tmp_path))
    with pytest.raises(ValueError):
        exportador.salvar_json("../fora", [])

def test_nome_analise_e_legivel_e_seguro():
    nome = exportador.nome_analise("C:/x/../exemplo semgrep.sarif")
    assert nome.endswith("_exemplo-semgrep")
    assert exportador._RE_NOME.fullmatch(nome)


def test_exportadores_gravam_em_pasta_por_analise(monkeypatch, tmp_path):
    monkeypatch.setattr(exportador, "DIR_RESULTADOS", str(tmp_path))
    achados = exportador.consolidar([VULN], [{**OK, "status": "ok"}])
    nome = exportador.nome_analise("exemplo.sarif")
    assert exportador.salvar_json(nome, achados) == os.path.join(str(tmp_path), nome, "relatorio_final.json")
    assert exportador.gerar_pdf(nome, achados) == os.path.join(str(tmp_path), nome, "relatorio_seguranca.pdf")


def test_exportador_exige_nome_de_analise(monkeypatch, tmp_path):
    monkeypatch.setattr(exportador, "DIR_RESULTADOS", str(tmp_path))
    with pytest.raises(ValueError):
        exportador.salvar_json(None, [])

def test_fallback_loga_mensagem_curta_em_portugues(monkeypatch, caplog):
    _fakes(monkeypatch, {"erro": "Gemini indisponível no momento devido ao tráfego intenso."}, OK)
    with caplog.at_level("WARNING"):
        r = analisador.analisar_vulnerabilidade_hibrida(dict(VULN), {}, {}, {})
    assert r["modelo"] == "ollama"
    assert "tráfego intenso. A análise será feita via Ollama" in caplog.text

def test_gemini_503_tenta_de_novo_antes_do_fallback(monkeypatch):
    from google.genai import errors as genai_errors
    from IA import gemini_service

    class Erro503(genai_errors.APIError):
        def __init__(self):
            self.code = 503

    class FakeModels:
        chamadas = 0

        def generate_content(self, **kwargs):
            FakeModels.chamadas += 1
            if FakeModels.chamadas < 3:
                raise Erro503()
            return type("R", (), {"text": json.dumps(OK)})()

    fake = type("C", (), {})()
    fake.models = FakeModels()
    monkeypatch.setattr(gemini_service, "_get_client", lambda: fake)
    monkeypatch.setattr(gemini_service.time, "sleep", lambda s: None)

    assert gemini_service.analisar_vulnerabilidade_gemini(dict(VULN), {}) == OK
    assert FakeModels.chamadas == 3

def test_gemini_503_vira_mensagem_amigavel():
    from google.genai import errors as genai_errors
    from IA.gemini_service import _erro_amigavel

    class ErroFalso(genai_errors.APIError):
        def __init__(self, code):  # não chama o __init__ do SDK (assinatura varia por versão)
            self.code = code

    assert _erro_amigavel(ErroFalso(503)) == "Gemini indisponível no momento devido ao tráfego intenso."
    assert "GEMINI_API_KEY" in _erro_amigavel(ErroFalso(403))



# ---------- API ----------
@pytest.fixture
def client():
    from main import app
    return TestClient(app)


def _upload(client, conteudo: bytes):
    return client.post("/api/v1/analisar-sarif",
                       files={"file": ("x.sarif", conteudo, "application/json")})


def test_api_json_invalido_retorna_422(client):
    assert _upload(client, b"isto nao e json").status_code == 422


def test_api_sarif_sem_runs_retorna_422(client):
    assert _upload(client, b'{"foo": 1}').status_code == 422


def test_api_arquivo_grande_retorna_413(client):
    assert _upload(client, b"{" + b" " * (5 * 1024 * 1024 + 10)).status_code == 413


def test_api_download_com_id_invalido_retorna_422(client):
    assert client.get("/api/v1/relatorio-pdf/nao-e-uuid").status_code == 422


def test_api_download_inexistente_retorna_404(client):
    assert client.get(f"/api/v1/relatorio-pdf/{uuid4()}").status_code == 404

def test_api_pasta_legivel_e_download_pelo_uuid(client, monkeypatch, tmp_path):
    _fakes(monkeypatch, OK, OK)
    monkeypatch.setattr(exportador, "DIR_RESULTADOS", str(tmp_path))
    corpo = _upload(client, json.dumps(_sarif()).encode()).json()

    pastas = os.listdir(tmp_path)
    assert len(pastas) == 1 and pastas[0].endswith(f"_x_{corpo['analise_id'][:8]}")
    assert client.get(corpo["download_pdf_url"]).status_code == 200

    # mesmo prefixo de 8 caracteres, ID completo diferente -> não pode baixar
    falso = corpo["analise_id"][:8] + "0" * 24
    assert client.get(f"/api/v1/relatorio-pdf/{falso}").status_code == 404

def test_api_fluxo_completo(client, monkeypatch, tmp_path):
    _fakes(monkeypatch, OK, OK)
    monkeypatch.setattr(exportador, "DIR_RESULTADOS", str(tmp_path))

    r = _upload(client, json.dumps(_sarif()).encode())
    assert r.status_code == 200
    corpo = r.json()
    assert corpo["total_achados"] == 1
    assert corpo["achados"][0]["analise_ia"]["modelo"] == "gemini"
    assert corpo["download_pdf_url"].startswith("/api/v1/relatorio-pdf/")

    pdf = client.get(corpo["download_pdf_url"])
    assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf"