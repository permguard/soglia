#!/usr/bin/env bash
set -euo pipefail
mkdir -p '/sys/fs/cgroup/system.slice/soglia-b6-target-target-outside-unit.service/executions'
exec sleep 60
