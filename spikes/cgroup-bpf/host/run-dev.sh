#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

host_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=common.sh
source "$host_dir/common.sh"

require_host
if [[ $# -eq 0 ]]; then
    set -- doctor
fi
if [[ $1 == run ]]; then
    diagnostic=false
    for argument in "$@"; do
        if [[ $argument == --only || $argument == --from ]]; then
            diagnostic=true
        fi
    done
    if [[ $diagnostic != true ]]; then
        echo "development VM refuses authoritative run; use --only TEST or --from TEST" >&2
        exit 13
    fi
fi
vm=${SOGLIA_SPIKE_DEV_VM:-soglia-spike-dev}
config=$(mktemp -t soglia-spike-lima.XXXXXX.yaml)
trap 'rm -f "$config"' EXIT
render_lima "$config"
ensure_vm "$vm" "$config"
provision_and_build "$vm"

run_guest "$vm" "$@"
