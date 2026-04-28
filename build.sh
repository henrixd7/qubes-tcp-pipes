#!/bin/bash
set -e

OUT="qubes-tcp-pipes.py"

# Add shebang line and concatenate modules in dependency order so the
# single-file build has all symbols available before they are referenced.
{
  echo '#!/usr/bin/env python3'
  cat \
    app/utils.py \
    app/models.py \
    app/cache.py \
    app/qubes.py \
    app/ui.py \
    main.py
} > "$OUT"

chmod +x "$OUT"
echo "Built $OUT ($(wc -l < "$OUT") lines)"
