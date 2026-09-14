"""Identical head/tail token selection for neural fine-tuning and serving."""


def tokenize_texts(encoder, texts):
    tokens = encoder.tokenizer(texts, add_special_tokens=True, truncation=False, verbose=False)['input_ids']
    capacity = encoder.max_seq_length
    if capacity < 4:
        raise ValueError('Encoder token budget is too small')
    inputs = []
    for ids in tokens:
        if len(ids) > capacity:
            left = capacity // 2
            ids = ids[:left] + ids[-(capacity - left):]
        # Slice the encoded sequence, preserving both boundary special tokens.
        inputs.append({'input_ids': ids, 'attention_mask': [1] * len(ids)})
    return {key: value.to(encoder.device) for key, value in
            encoder.tokenizer.pad(inputs, padding=True, return_tensors='pt').items()}


def embed(encoder, texts, batch_size=16):
    import numpy as np
    import torch
    encoder.eval()
    batches = []
    with torch.inference_mode():
        for start in range(0, len(texts), batch_size):
            features = tokenize_texts(encoder, texts[start:start + batch_size])
            vectors = torch.nn.functional.normalize(encoder(features)['sentence_embedding'], dim=1)
            batches.append(vectors.cpu().numpy())
    return np.concatenate(batches) if batches else np.empty((0, encoder.get_sentence_embedding_dimension()))
