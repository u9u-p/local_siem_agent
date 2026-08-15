#!/usr/bin/env bash
# Drive a batch of Stage 1 blocks unattended.
#
#   ./bench/sweep.sh candidates    # ~6h measured, decides the pick
#   ./bench/sweep.sh reference     # ~1.7h, explains it
#
# Blocks are ordered cheapest-first so an interrupted batch still leaves the widest
# spread of results. A failing block is logged and the sweep continues -- one model
# that cannot run must not cost the other eleven.
#
# Each block appends to bench/results/sweep-<batch>.log; per-run detail lands in each
# block's own runs.jsonl, which bench/score.py reads.
set -u

BATCH="${1:-candidates}"
STAGE="${2:-screen}"
LOG="bench/results/sweep-${BATCH}.log"
mkdir -p bench/results

# "model|effort" — empty effort leaves the model on its own default.
case "$BATCH" in
  candidates)
    BLOCKS=(
      "nemotron-3-nano:4b|"
      "lfm2.5:8b-a1b-q4_K_M|"
      "gpt-oss:20b|low"
      "gemma4:latest|"
      "lfm2:24b-a2b|"
      "mistral-small3.2|"
      "gemma4:26b-a4b-it-qat|"
      "muse-glimmer:30b|low"
      "qwen3.5:9b|low"
      "qwen3.6:27b|low"
      "muse-glimmer:30b|"
      "gemma4:12b|"
    ) ;;
  reference)
    BLOCKS=(
      "gpt-oss:120b|low"
      "qwen3.6:35b-a3b|low"
      "glm-4.7-flash|low"
      # Kept despite failing the Stage 0 gate: it costs 0 min (the loader rejects it
      # before generation) and the logged failure is the evidence that a ternary build
      # does not load under Ollama -- `tensor "output.weight" size overflow`.
      "hf.co/prism-ml/Ternary-Bonsai-27B-gguf:Q2_0|"
      # Dropped: qwen3.6:27b-bf16, ~5.3h for a Q4-vs-bf16 comparison on a model already
      # out on both speed (786s/alert at Q4) and footprint (17.2 GB of a 17.5 GB
      # ceiling). The quantisation question is worth asking of a model still in
      # contention -- gemma4:26b-a4b-it-qat, QAT vs PTQ -- not of one that is not.
    ) ;;
  *) echo "unknown batch '$BATCH' (candidates|reference)" >&2; exit 2 ;;
esac

started=$(date +%s)
echo "=== $BATCH / $STAGE — ${#BLOCKS[@]} blocks — $(date)" | tee -a "$LOG"

for block in "${BLOCKS[@]}"; do
  model="${block%%|*}"
  effort="${block##*|}"
  args=(--model "$model" --stage "$STAGE")
  [ -n "$effort" ] && args+=(--effort "$effort")

  t0=$(date +%s)
  echo "--- $model @ ${effort:-default} — $(date +%H:%M:%S)" | tee -a "$LOG"

  if .venv/bin/python -m bench.run "${args[@]}" >>"$LOG" 2>&1; then
    echo "    ok   $(( ($(date +%s) - t0) / 60 )) min" | tee -a "$LOG"
  else
    # Keep going: a model that cannot run is a result, and eleven others are waiting.
    echo "    FAIL $(( ($(date +%s) - t0) / 60 )) min — see $LOG" | tee -a "$LOG"
  fi

  # Free the block's model before the next loads. Without this two large models can
  # be resident at once, and 55GB + 65GB does not fit 128GB alongside KV cache.
  ollama stop "$model" >/dev/null 2>&1 || true
done

echo "=== $BATCH done in $(( ($(date +%s) - started) / 60 )) min — $(date)" | tee -a "$LOG"
echo "score with: .venv/bin/python -m bench.score --stage $STAGE"
