#!/bin/bash

set -euo pipefail

if [[ -f "venv/bin/activate" ]]; then
    . venv/bin/activate
fi

python3 -m wifi_launchpad "$@"
