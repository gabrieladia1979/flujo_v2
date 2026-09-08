import os
from huggingface_hub import hf_hub_download

# Carpeta de destino en el servidor de flujo_v2
MODEL_DIR = os.path.join(os.path.dirname(__file__), "model")
os.makedirs(MODEL_DIR, exist_ok=True)

# Repositorio oficial de Qwen 2.5 3B en formato GGUF
REPO_ID = "Qwen/Qwen2.5-3B-Instruct-GGUF"
# Elegimos la cuantización Q4_K_M que ofrece el mejor equilibrio (pesa ~2GB y es rapidísimo)
FILENAME = "qwen2.5-3b-instruct-q4_k_m.gguf"

print(f"Iniciando descarga de {FILENAME} desde HuggingFace...")
print(f"El modelo pesa unos 2 GB, esto puede tardar un poco dependiendo de tu internet.")

# Descargamos (huggingface_hub maneja reintentos y caché)
local_path = hf_hub_download(
    repo_id=REPO_ID,
    filename=FILENAME,
    local_dir=MODEL_DIR,
    local_dir_use_symlinks=False
)

print(f"\n✅ ¡Descarga completada con éxito!")
print(f"📍 Modelo guardado en: {local_path}")
