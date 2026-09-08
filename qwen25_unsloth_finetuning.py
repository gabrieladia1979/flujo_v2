# ==============================================================================
# SCRIPT PARA GOOGLE COLAB: FINE-TUNING DE QWEN 2.5 3B CON UNSLOTH (CHATML)
# ==============================================================================

# --- CELDA 1: Instalacion de dependencias ---
# !pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
# !pip install --no-deps xformers "trl<0.9.0" peft accelerate bitsandbytes

# --- CELDA 2: Cargar el Modelo Base ---
from unsloth import FastLanguageModel
import torch

max_seq_length = 4096
dtype = None
load_in_4bit = True

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name = "unsloth/Qwen2.5-3B-Instruct",
    max_seq_length = max_seq_length,
    dtype = dtype,
    load_in_4bit = load_in_4bit,
)

model = FastLanguageModel.get_peft_model(
    model,
    r = 32,
    target_modules = ["q_proj", "k_proj", "v_proj", "o_proj",
                      "gate_proj", "up_proj", "down_proj",],
    lora_alpha = 32,
    lora_dropout = 0, 
    bias = "none",    
    use_gradient_checkpointing = "unsloth", 
    random_state = 3407,
    use_rslora = True,
    loftq_config = None,
)


# --- CELDA 3: Preparar el Dataset ChatML ---
from datasets import load_dataset
from unsloth.chat_templates import get_chat_template

tokenizer = get_chat_template(
    tokenizer,
    chat_template = "chatml"
)

def formatear_mensajes(examples):
    conversaciones = examples["messages"]
    textos = [tokenizer.apply_chat_template(convo, tokenize=False, add_generation_prompt=False) for convo in conversaciones]
    return {"text": textos}

dataset = load_dataset("json", data_files="dataset_slm_chatml.jsonl", split="train")
dataset = dataset.map(formatear_mensajes, batched = True)
dataset = dataset.train_test_split(test_size=0.1, seed=42)
train_dataset = dataset["train"]
eval_dataset = dataset["test"]


# --- CELDA 4: Entrenamiento ---
from trl import SFTTrainer
from transformers import TrainingArguments, EarlyStoppingCallback

trainer = SFTTrainer(
    model = model,
    tokenizer = tokenizer,
    train_dataset = train_dataset,
    eval_dataset = eval_dataset,
    dataset_text_field = "text",
    max_seq_length = max_seq_length,
    dataset_num_proc = 2,
    packing = True,
    args = TrainingArguments(
        per_device_train_batch_size = 2,
        gradient_accumulation_steps = 4,
        warmup_ratio = 0.1,
        num_train_epochs = 3,
        learning_rate = 2e-4,
        fp16 = not torch.cuda.is_bf16_supported(),
        bf16 = torch.cuda.is_bf16_supported(),
        logging_steps = 5,
        evaluation_strategy = "steps", 
        eval_steps = 25,
        save_strategy = "steps", 
        save_steps = 25,
        load_best_model_at_end = True, 
        metric_for_best_model = "eval_loss",
        optim = "adamw_8bit",
        weight_decay = 0.01,
        lr_scheduler_type = "cosine",
        seed = 3407,
        output_dir = "outputs",
        neftune_noise_alpha = 5,
    ),
    callbacks=[EarlyStoppingCallback(early_stopping_patience=3)],
)

trainer_stats = trainer.train()


# --- CELDA 5: Exportar a GGUF ---
import os

print("Arrancando a exportar el GGUF final...")
model.save_pretrained_gguf("modelo_phisharg_q4", tokenizer, quantization_method = "q4_k_m")

# ATENCION: Estas comillas triples internas son texto normal, no las saques, son para crear el manual Modelfile_Ollama
modelfile_content = '''FROM ./modelo_phisharg_q4-unsloth.Q4_K_M.gguf
TEMPLATE """{{ if .System }}<|im_start|>system
{{ .System }}<|im_end|>
{{ end }}{{ if .Prompt }}<|im_start|>user
{{ .Prompt }}<|im_end|>
{{ end }}<|im_start|>assistant
"""
PARAMETER temperature 0.1
PARAMETER num_ctx 4096
PARAMETER stop "<|im_end|>"'''

with open("Modelfile_Ollama", "w", encoding="utf-8") as f:
    f.write(modelfile_content)
    
print("TERMINADO. Podes descargar modelo_phisharg_q4-unsloth.Q4_K_M.gguf")
