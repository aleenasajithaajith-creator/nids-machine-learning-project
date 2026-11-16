@echo off
title Network Intrusion Detection System
echo ========================================================
echo Starting Network Intrusion Detection System Web App...
echo ========================================================
cd /d "%~dp0"
streamlit run app/app.py
pause
