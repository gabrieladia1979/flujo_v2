import os
import json
import time
import pandas as pd
from tqdm import tqdm
import google.generativeai as genai
from google.generativeai.types import GenerationConfig

# Importamos las herramientas de tu compaÃ±ero de tesis directamente
from services.slm_explanation import (
    SLMExplanationContext,
    ExplanationEvidence,
    build_slm_prompt_messages,
    PHISHING_SUMMARY
)

# ==============================================================================
# CONFIGURACION
# ==============================================================================
API_KEY = os.environ.get("GEMINI_API_KEY", "TU_API_KEY_AQUI")
genai.configure(api_key=API_KEY, transport='rest')

MODEL_NAME = 'gemini-3.6-flash' 
model = genai.GenerativeModel(MODEL_NAME)

INPUT_CSV = r"..\Clasificador_PFI\SpaPhish_Master_Final_v5.csv"
OUTPUT_JSONL = "dataset_slm_chatml.jsonl"
CANTIDAD_A_GENERAR = 200
DELAY_SEGUNDOS = 4.1

# ==============================================================================
# PROMPT DEL PROFESOR (TEACHER MODEL)
# ==============================================================================
def armar_prompt_profesor(subject, body):
    return f"""
Sos el "Profesor" entrenando a una IA de ciberseguridad. Tu tarea es generar el par perfecto de [Contexto Tecnico] -> [Explicacion Amigable] para un correo de phishing.

CORREO DE PHISHING ARGENTINO:
Asunto: {subject}
Cuerpo: {body}

INSTRUCCIONES:
1. Analiza el correo e identifica 1 a 4 seniales (urgencia, amenaza, banco falso, etc.).
2. Genera el "context_evidence" (lo que veria nuestro sistema).
3. Genera la "final_explanation" (la respuesta que nuestro SLM debe aprender a dar al usuario final).
   - El summary DEBE ser EXACTAMENTE: "El clasificador determino que el correo es phishing."
   - Cada reason debe copiar exactamente el text de su evidencia (NO REFORMULES).
   - Usa SOLO acciones permitidas (ej: "do_not_click", "verify_via_official_channel", "report_to_it", "delete_email").

DEVUELVE EXCLUSIVAMENTE UN JSON con esta estructura exacta (sin formato markdown):
{{
  "context_evidence": [
    {{"evidence_id": "slot.urgencia", "text": "Extracto exacto del correo que muestra urgencia", "source": "observed_signal"}},
    {{"evidence_id": "slot.financiero", "text": "Extracto del correo sobre deudas o plata", "source": "observed_signal"}}
  ],
  "final_explanation": {{
    "summary": "El clasificador determino que el correo es phishing.",
    "reasons": [
      {{"evidence_id": "slot.urgencia", "text": "Extracto exacto del correo que muestra urgencia"}},
      {{"evidence_id": "slot.financiero", "text": "Extracto del correo sobre deudas o plata"}}
    ],
    "recommended_actions": [
      {{"code": "do_not_click", "text": "No abras enlaces ni adjuntos del correo."}},
      {{"code": "delete_email", "text": "Elimina el correo de tu bandeja de entrada."}}
    ]
  }}
}}
"""

def generar_dataset_slm():
    if not os.path.exists(INPUT_CSV):
        print(f"No se encontro el dataset {INPUT_CSV}.")
        return

    print("Cargando dataset de phishing...")
    df = pd.read_csv(INPUT_CSV)
    df_phishing = df[df['Label'] == 1].sample(frac=1, random_state=42).reset_index(drop=True)
    df_phishing = df_phishing.head(CANTIDAD_A_GENERAR)

    dataset_chatml = []
    
    # Cargar progreso previo
    if os.path.exists(OUTPUT_JSONL):
        with open(OUTPUT_JSONL, 'r', encoding='utf-8') as f:
            dataset_chatml = [json.loads(line) for line in f]
        print(f"Retomando: {len(dataset_chatml)} ejemplos ya generados.")
        df_phishing = df_phishing.iloc[len(dataset_chatml):]

    fallos_consecutivos = 0

    for index, row in tqdm(df_phishing.iterrows(), total=len(df_phishing), desc="Armando Dataset SLM"):
        subject = str(row.get('subject', ''))[:300]
        body = str(row.get('body', ''))[:2000]

        prompt = armar_prompt_profesor(subject, body)
        
        exito = False
        try:
            response = model.generate_content(
                prompt,
                generation_config=GenerationConfig(response_mime_type="application/json"),
                request_options={"timeout": 30.0}
            )
            
            datos_profesor = json.loads(response.text)
            
            evidencias = [ExplanationEvidence(**e) for e in datos_profesor['context_evidence']]
            contexto = SLMExplanationContext(
                is_phishing=True,
                risk_score=0.98,
                intent="robo_credenciales",
                authoritative_summary=PHISHING_SUMMARY,
                evidence=evidencias
            )
            
            messages = build_slm_prompt_messages(contexto)
            messages.append({
                "role": "assistant",
                "content": json.dumps(datos_profesor['final_explanation'], ensure_ascii=False)
            })
            
            registro_chatml = {"messages": messages}
            dataset_chatml.append(registro_chatml)
            
            with open(OUTPUT_JSONL, 'a', encoding='utf-8') as f:
                f.write(json.dumps(registro_chatml, ensure_ascii=False) + '\n')
            
            exito = True
            fallos_consecutivos = 0
                
        except Exception as e:
            error_str = str(e)
            fallos_consecutivos += 1
            
            if "429" in error_str:
                print(f"\nCuota alcanzada en indice {index}. Esperando 120 segundos...")
                time.sleep(120)
                
                # Segundo intento despues de la pausa larga
                try:
                    response = model.generate_content(
                        prompt,
                        generation_config=GenerationConfig(response_mime_type="application/json"),
                        request_options={"timeout": 30.0}
                    )
                    datos_profesor = json.loads(response.text)
                    evidencias = [ExplanationEvidence(**e) for e in datos_profesor['context_evidence']]
                    contexto = SLMExplanationContext(
                        is_phishing=True, risk_score=0.98, intent="robo_credenciales",
                        authoritative_summary=PHISHING_SUMMARY, evidence=evidencias
                    )
                    messages = build_slm_prompt_messages(contexto)
                    messages.append({"role": "assistant", "content": json.dumps(datos_profesor['final_explanation'], ensure_ascii=False)})
                    registro_chatml = {"messages": messages}
                    dataset_chatml.append(registro_chatml)
                    with open(OUTPUT_JSONL, 'a', encoding='utf-8') as f:
                        f.write(json.dumps(registro_chatml, ensure_ascii=False) + '\n')
                    exito = True
                    fallos_consecutivos = 0
                except Exception as e2:
                    print(f"\nSigue fallando tras espera larga: {str(e2)[:60]}")
            else:
                print(f"\nError en indice {index}: {error_str[:80]}")
        
        # PROTECCION: Si fallan 5 seguidos, es cuota diaria agotada. Frenamos.
        if fallos_consecutivos >= 5:
            print(f"\n*** CUOTA DIARIA AGOTADA ***")
            print(f"Se procesaron {len(dataset_chatml)} ejemplos exitosamente.")
            print(f"Relanza el script maniana y retomara desde donde quedo.")
            break
        
        if exito:
            time.sleep(DELAY_SEGUNDOS)

    print(f"\nDataset SLM guardado en {OUTPUT_JSONL}")
    print(f"Total de ejemplos: {len(dataset_chatml)}")

if __name__ == "__main__":
    generar_dataset_slm()
