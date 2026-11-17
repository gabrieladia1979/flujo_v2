"""LoRA SFT for reviewed explanations. Run on a CUDA GPU after preparation.

Example: python scripts/slm/train_qwen_sft.py artifacts/slm/sft --output artifacts/slm/qwen-lora
The result is a candidate adapter; evaluate it before merging/exporting GGUF.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", type=Path, default=Path("artifacts/slm/qwen-lora"))
    parser.add_argument("--model", default="Qwen/Qwen2.5-3B-Instruct")
    parser.add_argument("--epochs", type=float, default=2)
    parser.add_argument("--max-length", type=int, default=3072)
    args = parser.parse_args()

    import torch
    from datasets import load_dataset
    from peft import LoraConfig
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from trl import SFTConfig, SFTTrainer

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA GPU required for 4-bit LoRA training")
    data = load_dataset("json", data_files={"train": str(args.dataset / "train.jsonl"), "eval": str(args.dataset / "eval.jsonl")})
    if not data["train"] or not data["eval"]:
        raise ValueError("Both train and eval must contain reviewed examples")
    tokenizer = AutoTokenizer.from_pretrained(args.model, trust_remote_code=False)
    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        quantization_config=BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16),
        device_map="auto",
        trust_remote_code=False,
    )

    def prompt_completion(example):
        messages = example["messages"]
        return {
            "prompt": tokenizer.apply_chat_template(messages[:2], tokenize=False, add_generation_prompt=True),
            "completion": messages[2]["content"] + tokenizer.eos_token,
        }

    data = data.map(prompt_completion, remove_columns=data["train"].column_names)
    for split in ("train", "eval"):
        longest = max(len(tokenizer(row["prompt"] + row["completion"], add_special_tokens=False)["input_ids"]) for row in data[split])
        if longest > args.max_length:
            raise ValueError(f"{split} contains {longest} tokens; increase --max-length or shorten reviewed evidence to avoid truncating the answer")
    config = SFTConfig(
        output_dir=str(args.output),
        num_train_epochs=args.epochs,
        max_length=args.max_length,
        completion_only_loss=True,
        per_device_train_batch_size=1,
        per_device_eval_batch_size=1,
        gradient_accumulation_steps=8,
        gradient_checkpointing=True,
        learning_rate=1e-4,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        logging_steps=10,
        bf16=torch.cuda.is_bf16_supported(),
        fp16=not torch.cuda.is_bf16_supported(),
        report_to="none",
        seed=3407,
    )
    lora = LoraConfig(r=16, lora_alpha=32, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM", target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"])
    trainer = SFTTrainer(model=model, args=config, train_dataset=data["train"], eval_dataset=data["eval"], processing_class=tokenizer, peft_config=lora)
    trainer.train()
    trainer.save_model(str(args.output / "adapter"))
    tokenizer.save_pretrained(str(args.output / "adapter"))


if __name__ == "__main__":
    main()
