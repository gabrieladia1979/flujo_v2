# Usar una imagen oficial y super liviana de Python
FROM python:3.11-slim

# Establecer el directorio de trabajo en el contenedor
WORKDIR /app

# Copiar el archivo de dependencias primero (para optimizar caché de Docker)
COPY requirements.txt .

# Instalar dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Descargar el modelo de idioma spaCy (requerido para lematización NLP)
RUN python -m spacy download es_core_news_sm

# Copiar el resto del código (incluyendo el modelo XGBoost .pkl)
COPY . .

# Exponer el puerto que va a usar Flask/Gunicorn
EXPOSE 8080

# Comando para iniciar el servidor FastAPI
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
