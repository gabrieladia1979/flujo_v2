import os
import re

with open('services/analyzer.py', 'r', encoding='utf-8') as f:
    code = f.read()

# Fix regex escapes that got broken
code = code.replace("r'https?://[^\\s<>\\\"\\')\\]]+|www\\.[^\\s<>\\\"\\')\\]]+'", "r'https?://[^\\s<>\"\\'\\)\\]]+|www\\.[^\\s<>\"\\'\\)\\]]+'")
code = code.replace("r'\\b[a-záéíóúüñ]+\\b'", "r'\\b[a-záéíóúüñ]+\\b'")

with open('services/analyzer.py', 'w', encoding='utf-8') as f:
    f.write(code)
