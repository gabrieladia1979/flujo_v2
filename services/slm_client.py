import os
import json
import time
import logging
from typing import Optional, Dict, Any

from pydantic import ValidationError
from services.slm_explanation import (
    SLMExplanationContext,
    build_slm_prompt_messages,
    render_server_fallback
)

logger = logging.getLogger(__name__)

# Configuramos la ruta del modelo descargado
MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "model", "qwen2.5-3b-instruct-q4_k_m.gguf")

# Instancia global (singleton lazy)
_slm_instance = None

def get_slm_instance():
    """Inicializa y cachea el modelo localmente para evitar recargas."""
    global _slm_instance
    if _slm_instance is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Modelo GGUF no encontrado en {MODEL_PATH}")
        
        try:
            # Importación lazy para no romper la app si no está instalada la librería
            from llama_cpp import Llama
            
            _slm_instance = Llama(
                model_path=MODEL_PATH,
                n_ctx=2048,           # Contexto suficiente para los fragmentos de email
                n_gpu_layers=0,       # 0 = Solo CPU. Ajustar si hay GPU
                n_threads=4,          # Usamos 4 hilos por defecto
                verbose=False         # Desactivar logs ruidosos de C++
            )
        except ImportError:
            raise ImportError("Falta instalar llama-cpp-python. Ejecutar: pip install llama-cpp-python")
    return _slm_instance

def generate_slm_explanation(context: SLMExplanationContext) -> str:
    """
    Invoca al SLM local para generar la explicación estructurada en formato JSON.
    Devuelve un string JSON válido o el string del Fallback si falla.
    Aplica como máximo 1 reintento si el formato JSON es inválido.
    """
    start_time = time.time()
    
    try:
        messages = build_slm_prompt_messages(context)
        llm = get_slm_instance()
        
        # Intento 1
        response = llm.create_chat_completion(
            messages=messages,
            temperature=0.1,
            max_tokens=300, 
            response_format={"type": "json_object"}
        )
        raw_output = response['choices'][0]['message']['content'].strip()
        
        try:
            json.loads(raw_output)
            return raw_output
        except json.JSONDecodeError:
            logger.warning("Fallo el parseo JSON. Iniciando 1 reintento de corrección.")
            # Intento 2 (Reintento con instrucción de corrección)
            messages.append({"role": "assistant", "content": raw_output})
            messages.append({"role": "user", "content": "El formato devuelto no es un JSON válido. Por favor, corregilo y devolvé ÚNICAMENTE el JSON válido sin texto adicional."})
            
            retry_response = llm.create_chat_completion(
                messages=messages,
                temperature=0.1,
                max_tokens=300, 
                response_format={"type": "json_object"}
            )
            retry_output = retry_response['choices'][0]['message']['content'].strip()
            
            # Validamos el reintento
            json.loads(retry_output)
            
            latency = time.time() - start_time
            logger.info(f"SLM Inference (con reintento) completada en {latency:.2f}s")
            return retry_output
            
    except Exception as e:
        latency = time.time() - start_time
        logger.error(f"Fallo en SLM (Fallback activado). Latencia: {latency:.2f}s. Error: {str(e)}")
        
        # Fallback seguro garantizado
        return render_server_fallback(context)
