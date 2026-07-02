#!/usr/bin/env bash
# ============================================================
# Compila el backend en Linux/macOS CON captura real via libpcap.
#
# Requisitos (una sola vez):
#   Linux (Debian/Ubuntu): sudo apt-get install libpcap-dev
#   macOS: libpcap viene con Xcode Command Line Tools
#
# Uso:  ./build.sh
# Genera "monitor" con captura real. Para capturar tráfico real
# hace falta correrlo con permisos (sudo ./monitor) o dar la
# capability: sudo setcap cap_net_raw,cap_net_admin=eip ./monitor
# ============================================================
set -e

gcc -std=c11 -O2 -DHAVE_PCAP -Wall -Iinclude \
    src/main.c src/api_server.c src/data_reader.c src/detector.c src/search.c src/sort.c src/viewmodel.c \
    -o monitor -lpcap -lpthread

echo "OK -> ./monitor generado con captura real (libpcap)."
echo "Para capturar trafico real: sudo ./monitor"
echo "  (o) sudo setcap cap_net_raw,cap_net_admin=eip ./monitor && ./monitor"
