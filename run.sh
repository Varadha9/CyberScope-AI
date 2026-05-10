#!/bin/bash
export PYTHONPATH="/home/varad/.local/lib/python3.13/site-packages:/usr/lib/python3/dist-packages:$PYTHONPATH"
cd /home/varad/CyberScope-AI
sudo fuser -k 5000/tcp 2>/dev/null
sleep 1
sudo -E python3 app.py
