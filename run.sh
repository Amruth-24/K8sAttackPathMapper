#!/bin/bash
echo "[*] Building GuardV2 Docker Image..."
docker build -t guardv2 .
echo "[*] Running Analysis..."
docker run -it --rm -v ~/.kube:/root/.kube -v "${PWD}:/app" --network host guardv2