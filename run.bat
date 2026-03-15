@echo off
:: Clean up old report on host before running
if exist Full_Security_Audit.pdf del /f Full_Security_Audit.pdf

echo [*] Launching shadowtracerv1 Analysis...
docker run -it --rm ^
  -v "%USERPROFILE%\.kube:/root/.kube" ^
  -v "%cd%:/app/reports" ^
  --network host ^
  shadowtracerv1