#!/bin/sh
set -eu

IMAGE="${OPENSHELL_DEFENCE_IMAGE:-reverseopenshell-runner:dev}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

for source in sensor-a sensor-b; do
  sandbox="defence-${source}-shield"
  policy="policies/defence-${source}.yaml"
  echo "Creating ${sandbox} with ${policy}"
  openshell sandbox create \
    --name "$sandbox" \
    --from "$IMAGE" \
    --policy "$policy" \
    --detach \
    --cpu 1 \
    --memory 256Mi \
    -- sleep infinity
done
