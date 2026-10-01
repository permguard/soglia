#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Exact, evidence-producing teardown for transient delegated qualification units.

SYSTEMD_CGROUP_STOP_WAIT_ITERATIONS=${SYSTEMD_CGROUP_STOP_WAIT_ITERATIONS:-200}
SYSTEMD_CGROUP_STOP_WAIT_INTERVAL=${SYSTEMD_CGROUP_STOP_WAIT_INTERVAL:-0.05}

systemd_cgroup_capture_file() {
  local path=$1 output=$2
  if [[ -f $path ]]; then
    cat "$path" > "$output"
  else
    printf '%s\n' ABSENT > "$output"
  fi
}

systemd_cgroup_record_stop_state() {
  local unit_cgroup=$1 runtime_cgroup=$2 evidence_dir=$3 suffix=$4
  systemd_cgroup_capture_file "$unit_cgroup/cgroup.events" \
    "$evidence_dir/unit-cgroup.events.$suffix.txt"
  systemd_cgroup_capture_file "$unit_cgroup/cgroup.procs" \
    "$evidence_dir/unit-cgroup.procs.$suffix.txt"
  systemd_cgroup_capture_file "$unit_cgroup/cgroup.subtree_control" \
    "$evidence_dir/unit-cgroup.subtree_control.$suffix.txt"
  systemd_cgroup_capture_file "$runtime_cgroup/cgroup.events" \
    "$evidence_dir/runtime-cgroup.events.$suffix.txt"
  systemd_cgroup_capture_file "$runtime_cgroup/cgroup.procs" \
    "$evidence_dir/runtime-cgroup.procs.$suffix.txt"
  systemd_cgroup_capture_file "$runtime_cgroup/cgroup.subtree_control" \
    "$evidence_dir/runtime-cgroup.subtree_control.$suffix.txt"
}

stop_and_prune_unit_cgroup() {
  local requested_unit=$1 evidence_dir=${2:-}
  local unit=${requested_unit%.service}
  local service="$unit.service"
  local unit_cgroup="/sys/fs/cgroup/system.slice/$service"
  local runtime_cgroup="$unit_cgroup/runtime"
  local cursor= classification=NATIVE stop_status=0 active_state

  if [[ -n $evidence_dir ]]; then
    mkdir -p "$evidence_dir"
    systemd --version > "$evidence_dir/systemd-version.txt"
    cursor=$(journalctl -n 0 --show-cursor --no-pager | sed -n 's/^-- cursor: //p')
    systemd_cgroup_record_stop_state "$unit_cgroup" "$runtime_cgroup" "$evidence_dir" before-stop
  fi

  if [[ ! -d $unit_cgroup ]] \
    && [[ $(systemctl show "$service" -p LoadState --value 2>/dev/null || true) == not-found ]]; then
    [[ -z $evidence_dir ]] || printf '%s\n' "$classification" \
      > "$evidence_dir/stop-classification.txt"
    return 0
  fi

  systemctl stop "$service" >/dev/null 2>&1 || stop_status=$?
  journalctl --sync
  if [[ -n $evidence_dir ]]; then
    if [[ -n $cursor ]]; then
      SYSTEMD_COLORS=0 journalctl -u "$service" --after-cursor "$cursor" \
        -o cat --no-pager --no-hostname > "$evidence_dir/stop-journal.txt"
      SYSTEMD_COLORS=0 journalctl _PID=1 --after-cursor "$cursor" \
        -o cat --no-pager --no-hostname > "$evidence_dir/stop-systemd-journal.txt"
    else
      : > "$evidence_dir/stop-journal.txt"
      : > "$evidence_dir/stop-systemd-journal.txt"
    fi
    printf '%s\n' "$stop_status" > "$evidence_dir/systemctl-stop-status.txt"
    systemd_cgroup_record_stop_state "$unit_cgroup" "$runtime_cgroup" "$evidence_dir" after-stop
  fi
  if [[ $stop_status -ne 0 ]]; then
    [[ -z $evidence_dir ]] || printf '%s\n' FAIL_SYSTEMCTL_STOP \
      > "$evidence_dir/stop-classification.txt"
    return 1
  fi

  if [[ -d $unit_cgroup ]]; then
    local populated_files
    populated_files=$(find "$unit_cgroup" -xdev -name cgroup.procs -type f -print)
    while IFS= read -r procs; do
      [[ -z $procs || ! -s $procs ]] && continue
      if [[ -n $evidence_dir ]]; then
        cp "$procs" "$evidence_dir/populated-$(printf '%s' "$procs" | sha256sum | cut -c1-12).txt"
        printf '%s\n' FAIL_RUNTIME_POPULATED > "$evidence_dir/stop-classification.txt"
      fi
      return 1
    done <<< "$populated_files"
  fi

  for _ in $(seq 1 "$SYSTEMD_CGROUP_STOP_WAIT_ITERATIONS"); do
    active_state=$(systemctl show "$service" -p ActiveState --value 2>/dev/null || true)
    if [[ $active_state == inactive && ! -d $unit_cgroup ]]; then
      [[ -z $evidence_dir ]] || printf '%s\n' "$classification" \
        > "$evidence_dir/stop-classification.txt"
      return 0
    fi
    sleep "$SYSTEMD_CGROUP_STOP_WAIT_INTERVAL"
  done

  active_state=$(systemctl show "$service" -p ActiveState --value 2>/dev/null || true)
  local parent_children= runtime_children=
  parent_children=$(find "$unit_cgroup" -mindepth 1 -maxdepth 1 -type d \
    -printf '%f\n' 2>/dev/null | sort)
  if [[ -d $runtime_cgroup ]]; then
    runtime_children=$(find "$runtime_cgroup" -mindepth 1 -maxdepth 1 -type d \
      -printf '%f\n' 2>/dev/null | sort)
  fi

  local exact_empty_shape=false
  if [[ -z $parent_children ]]; then
    exact_empty_shape=true
  elif [[ $parent_children == runtime ]] \
    && [[ -z $runtime_children ]] \
    && [[ -f $runtime_cgroup/cgroup.events ]] \
    && grep -Fxq 'populated 0' "$runtime_cgroup/cgroup.events" \
    && [[ ! -s $runtime_cgroup/cgroup.procs ]]; then
    exact_empty_shape=true
  fi

  if [[ $active_state == inactive ]] \
    && [[ $exact_empty_shape == true ]] \
    && [[ -f $unit_cgroup/cgroup.events ]] \
    && grep -Fxq 'populated 0' "$unit_cgroup/cgroup.events" \
    && [[ ! -s $unit_cgroup/cgroup.procs ]]; then
    classification=SYSTEMD_PRUNE_RACE
    [[ ! -d $runtime_cgroup ]] || rmdir "$runtime_cgroup" || return 1
    rmdir "$unit_cgroup" || return 1
    [[ ! -e $unit_cgroup ]] || return 1
    if [[ -n $evidence_dir ]]; then
      jq -n --arg unit "$service" --arg classification "$classification" \
        --argjson wait_ms 10000 --arg shape "${parent_children:-EMPTY}" \
        '{unit:$unit,classification:$classification,wait_ms:$wait_ms,
          exact_empty_shape:$shape,unit_populated:false,runtime_populated:false,
          exact_rmdir_verified:true}' > "$evidence_dir/systemd-prune-race.json"
      printf '%s\n' "$classification" > "$evidence_dir/stop-classification.txt"
      systemd_cgroup_record_stop_state "$unit_cgroup" "$runtime_cgroup" "$evidence_dir" after-prune
    fi
    return 0
  fi

  if [[ -n $evidence_dir ]]; then
    printf '%s\n' "$parent_children" > "$evidence_dir/unit-child-cgroups.failure.txt"
    printf '%s\n' "$runtime_children" > "$evidence_dir/runtime-child-cgroups.failure.txt"
    printf '%s\n' "$active_state" > "$evidence_dir/unit-active-state.failure.txt"
    printf '%s\n' FAIL_UNEXPECTED_CGROUP_SHAPE > "$evidence_dir/stop-classification.txt"
  fi
  return 1
}
