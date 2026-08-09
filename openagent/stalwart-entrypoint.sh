#!/bin/sh
set -eu

config_path=/etc/stalwart/config.json

forward_signal() {
  if [ -n "${stalwart_pid:-}" ]; then
    kill -TERM "$stalwart_pid" 2>/dev/null || true
  fi
}
trap forward_signal TERM INT

while :; do
  started_in_bootstrap=false
  if [ ! -f "$config_path" ]; then
    started_in_bootstrap=true
  fi

  /usr/local/bin/stalwart --config "$config_path" &
  stalwart_pid=$!

  if [ "$started_in_bootstrap" = true ]; then
    while kill -0 "$stalwart_pid" 2>/dev/null && [ ! -f "$config_path" ]; do
      sleep 1
    done
    if kill -0 "$stalwart_pid" 2>/dev/null && [ -f "$config_path" ]; then
      echo "OpenAgent bootstrap completed; restarting Stalwart with persistent configuration."
      kill -TERM "$stalwart_pid"
      wait "$stalwart_pid" || true
      unset stalwart_pid
      continue
    fi
  fi

  wait "$stalwart_pid"
  exit_code=$?
  unset stalwart_pid
  exit "$exit_code"
done
