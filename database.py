from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

SQLALCHEMY_DATABASE_URL = "sqlite:///./feedback.db"
# En producción sería: "postgresql://usuario:pass@servidor/bd"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class UserFeedback(Base):
    """
    Tabla para almacenar la retroalimentación de los usuarios finales.
    Permite el reentrenamiento orgánico del modelo.
    """
    __tablename__ = "user_feedback"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Datos del correo (anonimizados o resumidos)
    subject_hash = Column(String, index=True)
    sender_domain = Column(String)
    
    # Resultados originales del modelo
    original_risk_score = Column(Float)
    original_is_phishing = Column(Boolean)
    
    # Feedback del usuario
    user_reported_is_phishing = Column(Boolean) # ¿El usuario dice que es Phishing?
    user_comment = Column(String, nullable=True)

# Crear las tablas
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
