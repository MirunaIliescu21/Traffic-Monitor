#!/bin/bash
#
# Simulează un canal de beaconing C2: cereri HTTP repetate, la interval fix,
# către o singură destinație. Folosit pentru a testa detecția de
# CONCENTRARE + REGULARITATE din baseline.py.
#
# Rulare: ./simulate_beaconing.sh
# Oprire: Ctrl+C
#
# IMPORTANT: rulează acest script ÎN PARALEL cu collector.py, într-un
# terminal separat, ca traficul generat aici să fie și el înregistrat.

TARGET_IP="93.184.216.34"   # IP public de test (poți schimba cu altul real)
TARGET_PORT="80"
INTERVAL_SECONDS=60
TIMEOUT_SECONDS=2

echo "[*] Simulez beaconing catre http://${TARGET_IP}:${TARGET_PORT}/"
echo "[*] Interval: ${INTERVAL_SECONDS}s, timeout per cerere: ${TIMEOUT_SECONDS}s"
echo "[*] Ctrl+C pentru oprire"
echo ""

count=0
while true; do
    count=$((count + 1))
    timestamp=$(date '+%H:%M:%S')
    curl -s -m "${TIMEOUT_SECONDS}" "http://${TARGET_IP}:${TARGET_PORT}/" > /dev/null 2>&1
    echo "[${timestamp}] cerere #${count} trimisa"
    sleep "${INTERVAL_SECONDS}"
done
