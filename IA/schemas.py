# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, Samuel de Oliveira Marques, Vladmir Aleiksander Pugliesi Vilasboas di Araujo
# RiskLayer ASPM - distribuído sob a licença BSD de 3 cláusulas (veja LICENSE.md).

from pydantic import BaseModel, field_validator


class AnaliseIA(BaseModel):
    """Contrato de resposta dos modelos. O 'risco' NÃO faz parte: quem decide é o código."""

    impacto: str
    recomendacao: str

    @field_validator("impacto", "recomendacao")
    @classmethod
    def _texto_valido(cls, valor: str) -> str:
        valor = valor.strip()
        if len(valor) < 10:
            raise ValueError("texto curto demais")
        return valor[:1200]