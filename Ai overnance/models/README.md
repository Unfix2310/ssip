# Semantic Model Assets

Place these runtime assets in this directory for the NLP semantic layer:

- `lid.176.ftz` (fastText language identifier model)
- `semantic_setfit_int8.onnx` (SetFit/MuRIL-compatible ONNX model)
- `tokenizer.json` (tokenizer used to build the ONNX model)

The gateway will automatically fall back to lexical classification if these files are missing.

## Recommended build flow

1. Fine-tune a multilingual classifier (for example MuRIL backbone + SetFit labels).
2. Export to ONNX with sequence classification head.
3. Apply INT8 quantization with ONNX Runtime tooling.
4. Copy exported `model_quantized.onnx` to `semantic_setfit_int8.onnx`.
5. Copy the exact tokenizer used at training time to `tokenizer.json`.
