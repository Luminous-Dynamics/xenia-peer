#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

checks=(
  scripts/check_transport_session_profile_v10.py
  scripts/check_transport_session_profile_v11.py
  scripts/check_transport_availability_v12.py
  scripts/check_transport_presession_v13.py
  scripts/check_application_flow_control_v14.py
  scripts/check_application_teardown_v15.py
  scripts/check_application_lane_latency_v16.py
  scripts/check_application_lane_recovery_v17.py
  scripts/check_application_runtime_evidence_v18.py
  scripts/check_application_runtime_assurance_v19.py
  scripts/check_application_file_staging_v20.py
  scripts/check_application_receive_staging_v21.py
  scripts/check_application_transfer_source_v22.py
)
models=(
  scripts/model_check_transport_session_profile_v1.py
  scripts/model_check_transport_session_v11.py
  scripts/model_check_transport_availability_v12.py
  scripts/model_check_transport_presession_v13.py
  scripts/model_check_application_flow_control_v14.py
  scripts/model_check_application_teardown_v15.py
  scripts/model_check_application_lane_latency_v16.py
  scripts/model_check_application_lane_recovery_v17.py
  scripts/model_check_application_runtime_evidence_v18.py
  scripts/model_check_application_runtime_assurance_v19.py
  scripts/model_check_application_file_staging_v20.py
  scripts/model_check_application_receive_staging_v21.py
)

for script in "${checks[@]}" "${models[@]}"; do
  python3 "$script"
done
