from typing import Optional, List, Any
from pydantic import BaseModel, Field, model_validator


class MetadataSchema(BaseModel):
    asunto: Optional[str] = Field(default=None, max_length=1000)
    remitente_nombre: Optional[str] = Field(default=None, max_length=500)
    remitente_email: Optional[str] = Field(default=None, max_length=500)


class SecurityFeaturesSchema(BaseModel):
    """
    Características de seguridad extraídas de las cabeceras del correo.
    Todos los campos son opcionales con valores por defecto seguros.
    """
    # === Autenticación ===
    spf_result: str = "unknown"
    dkim_result: str = "unknown"
    dmarc_result: str = "unknown"
    compauth_result: str = "unknown"

    # === Detección de Spoofing ===
    return_path: str = ""
    reply_to: str = ""
    from_return_path_match: bool = True
    from_reply_to_match: bool = True
    sender_vs_from_match: bool = True

    # === Anti-Spam de Microsoft 365 ===
    scl: int = 0
    threat_category: str = "NONE"
    spam_filtering_verdict: str = ""
    auth_as: str = "unknown"
    bcl: int = 0

    # === Origen ===
    originating_ip: str = ""
    originating_country: str = ""
    x_mailer: str = ""
    received_hop_count: int = 0
    is_trusted_domain: Optional[bool] = False

    # === Adjuntos ===
    attachment_count: int = 0
    attachment_types: Optional[List[str]] = None
    has_executable_attachment: bool = False

    # === Destinatarios ===
    to_count: int = 1
    cc_count: int = 0

    # === Metadata ===
    internet_message_id: str = ""
    has_headers: bool = False


class SecurityAdjustment(BaseModel):
    """Representa un ajuste individual aplicado por una regla heurística."""
    rule: str
    delta: float
    description: str


class EmailPayloadSchema(BaseModel):
    metadata: MetadataSchema
    contenido: Optional[str] = Field(default=None, max_length=1000000) # Máximo 1MB de texto
    cabeceras_red: Optional[Any] = None
    security_features: Optional[SecurityFeaturesSchema] = None

    @model_validator(mode="before")
    @classmethod
    def allow_body_alias(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if not data.get("contenido") and data.get("body"):
                data["contenido"] = data["body"]
        return data


class ContentSignal(BaseModel):
    rule: str
    description: str


class AnalysisResultSchema(BaseModel):
    is_phishing: bool
    risk_score: float
    reason: str
    intent: Optional[str] = None
    slots_detectados: Optional[dict] = None
    security_adjustments: Optional[List[SecurityAdjustment]] = None
    slm_explanation: Optional[str] = None
    raw_model_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    decision_source: Optional[str] = None
    content_signals: List[ContentSignal] = Field(default_factory=list)

