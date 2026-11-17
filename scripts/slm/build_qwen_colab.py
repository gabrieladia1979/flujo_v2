"""Build a self-contained Colab notebook from the current explanation contract."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "notebooks" / "qwen_hybrid_xai_colab.ipynb"


def code(source: str) -> dict:
    return {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": source.splitlines(True)}


def markdown(source: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": source.splitlines(True)}


def writefile(path: str, source: str) -> dict:
    return code(f"%%writefile {path}\n" + source)


def build() -> None:
    cells = [
        markdown("""# Qwen 2.5 3B para explicar Hybrid XAI

Este notebook prepara **un solo ajuste LoRA** de Qwen. Hybrid conserva el veredicto. El notebook exige pares revisados de `context` y `explanation`; **no usa automáticamente** el dataset antiguo de 2.000 ejemplos.

Para probar el recorrido completo, podés subir `qwen_hybrid_demo_reviewed.jsonl`, generado desde 48 casos sintéticos inspeccionados del repositorio. Ese archivo sirve para verificar que el entrenamiento corre, no para medir rendimiento real ni reemplazar el Qwen del piloto.

Antes de ejecutar, elegí **Entorno de ejecución → Cambiar tipo de entorno de ejecución → GPU**. Una GPU T4 o superior puede servir, según la memoria disponible. Subí un JSONL con un objeto por línea: `case_id`, `source_id`, `reviewed: true`, `context`, `explanation`. Revisá manualmente cada evidencia con el correo de origen y la salida real de Hybrid. Quitá datos personales. Para Argentina, incluí casos legítimos y de suplantación de comercio electrónico, billeteras y bancos; una marca mencionada no demuestra autenticidad.

El resultado es un **adaptador candidato**, no un GGUF para producción. El piloto actual no se modifica. La disponibilidad y duración de GPU de Colab varían.
"""),
        code("""import sys, subprocess
subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-q', 'pydantic>=2,<3', 'transformers==4.57.3', 'trl==0.26.2', 'peft==0.18.0', 'datasets==4.4.1', 'accelerate', 'bitsandbytes'])
import torch
assert torch.cuda.is_available(), 'Activá una GPU en el entorno de ejecución de Colab.'
print('GPU:', torch.cuda.get_device_name(0))
"""),
        code("""from pathlib import Path
Path('services').mkdir(exist_ok=True)
Path('scripts/slm').mkdir(parents=True, exist_ok=True)
Path('services/__init__.py').touch()
"""),
        writefile("services/slm_explanation.py", (ROOT / "services" / "slm_explanation.py").read_text(encoding="utf-8")),
        writefile("scripts/slm/prepare_qwen_sft.py", (ROOT / "scripts/slm/prepare_qwen_sft.py").read_text(encoding="utf-8")),
        writefile("scripts/slm/train_qwen_sft.py", (ROOT / "scripts/slm/train_qwen_sft.py").read_text(encoding="utf-8")),
        markdown("""## 1. Subir los casos revisados

Seleccioná el JSONL de pares revisados. Si aparecen errores en la auditoría, corregí el archivo y volvé a ejecutar desde esta celda. El contenido de los correos no se imprime.
"""),
        code("""from google.colab import files
uploaded = files.upload()
assert len(uploaded) == 1, 'Subí exactamente un archivo JSONL de casos revisados.'
source_file = next(iter(uploaded))
assert source_file.lower().endswith('.jsonl'), 'El archivo debe ser JSONL.'
print('Archivo recibido:', source_file)
"""),
        code("""import json, subprocess, sys
subprocess.check_call([sys.executable, 'scripts/slm/prepare_qwen_sft.py', source_file, 'artifacts/slm/sft', '--eval-percent', '25'])
audit = json.loads(open('artifacts/slm/sft/audit.json', encoding='utf-8').read())
assert audit['counts'].get('total') == audit['counts'].get('accepted'), 'Hay registros rechazados: revisá la auditoría antes de entrenar.'
assert audit['train'] >= 20 and audit['eval'] >= 10, 'Se requieren al menos 20 casos de entrenamiento y 10 de evaluación de fuentes separadas.'
for split in ('train', 'eval'):
    labels = set()
    for line in open(f'artifacts/slm/sft/{split}.jsonl', encoding='utf-8'):
        row = json.loads(line)
        context = json.loads(row['messages'][1]['content'].split('\\n', 1)[1])
        labels.add(context['is_phishing'])
    assert labels == {True, False}, f'Faltan casos phishing o legítimos en {split}.'
print('Datos listos:', audit['train'], 'train /', audit['eval'], 'eval')
"""),
        markdown("""## 2. Entrenar y guardar

El entrenamiento descarga `Qwen/Qwen2.5-3B-Instruct` de Hugging Face. Montar Drive guarda el adaptador al finalizar; asegurate de tener espacio. Si Colab interrumpe la sesión antes de terminar, el resultado puede no haberse guardado.
"""),
        code("""from google.colab import drive
drive.mount('/content/drive')
"""),
        code("""subprocess.check_call([sys.executable, 'scripts/slm/train_qwen_sft.py', 'artifacts/slm/sft', '--output', 'artifacts/slm/qwen-lora'])
"""),
        code("""import shutil, time
from pathlib import Path
source = Path('artifacts/slm/qwen-lora/adapter')
assert (source / 'adapter_config.json').exists(), 'No se encontró el adaptador entrenado.'
target = Path('/content/drive/MyDrive/PhishARG/qwen-hybrid-lora-' + time.strftime('%Y%m%d-%H%M%S'))
target.parent.mkdir(parents=True, exist_ok=True)
shutil.copytree(source, target)
shutil.copy2('artifacts/slm/sft/audit.json', target / 'data_audit.json')
print('Adaptador candidato guardado en:', target)
"""),
        markdown("""## Después del entrenamiento

Evaluá el candidato con correos argentinos **no usados** en entrenamiento ni evaluación, comprobá cada motivo con `validate_slm_output` y compará la tasa de respaldo con el Qwen base. Solo después conviene fusionar/exportar a GGUF y probarlo en el piloto. La pérdida de evaluación por sí sola no mide veracidad ni seguridad.
"""),
    ]
    notebook = {"cells": cells, "metadata": {"colab": {"name": OUTPUT.name, "provenance": []}, "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python"}}, "nbformat": 4, "nbformat_minor": 5}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(notebook, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(OUTPUT)


if __name__ == "__main__":
    build()
