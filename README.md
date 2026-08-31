# Proyecto Flujo

Este repositorio contiene el código fuente del proyecto Flujo.

## Requisitos Previos

Asegurate de tener Python instalado y luego instala las dependencias:

```bash
pip install -r requirements.txt
```

## Configuración del Modelo (¡Importante!)

Debido al tamaño de los archivos del modelo (como `model.safetensors`), la carpeta `model/` **no** está incluida en este repositorio para no exceder los límites de tamaño de GitHub.

**Pasos para configurar el modelo localmente:**

1.  Pedile a un compañero de equipo el archivo comprimido con la carpeta `model/`.
2.  Descomprimí el archivo.
3.  Colocá la carpeta `model/` en la raíz de este proyecto (al mismo nivel que este archivo `README.md`).

La estructura final debería verse así:
```text
Flujo/
├── model/
│   └── model.safetensors
├── README.md
├── requirements.txt
└── ... resto de los archivos ...
```

*(Nota: La carpeta `model/` está incluida en el archivo `.gitignore` y no se subirá al repositorio remoto accidentalmente).*
