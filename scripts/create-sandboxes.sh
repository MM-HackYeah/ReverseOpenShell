#!/bin/sh
set -eu

IMAGE="${OPENSHELL_RUNNER_IMAGE:-reverseopenshell-runner:dev}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

for tier in untrusted readonly write; do
  echo "Creating tier-${tier} with ${tier}.yaml"
  openshell sandbox create \
    --name "tier-${tier}" \
    --from "$IMAGE" \
    --policy "policies/${tier}.yaml" \
    --detach \
    -- sleep infinity
done
