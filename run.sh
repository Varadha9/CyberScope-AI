#!/bin/bash
export PYTHONPATH="/home/varad/.local/lib/python3.13/site-packages:/usr/lib/python3/dist-packages:$PYTHONPATH"
export CYBERSCOPE_SUDO_PASS="dogs"
cd /home/varad/CyberScope-AI
echo "dogs" | sudo -S fuser -k 5000/tcp 2>/dev/null
sleep 1
echo "dogs" | sudo -SE python3 app.py
