#!/bin/bash
rm -f Full_Security_Audit.pdf
echo "[*] Launching shadowtracerv1 Analysis..."
docker run -it --rm \
  -v ~/.kube:/root/.kube \
  -v "$(pwd):/app/reports" \
  --network host \
  shadowtracerv1