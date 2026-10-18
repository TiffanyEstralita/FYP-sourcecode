@echo off
rem Double-click to run the LLM jobs unattended (LLM check + shortlist scoring,
rem with prompt v3 and with the VulnSC reranker).
rem One run stops by itself after 3 hours (configs/llm.yaml: max_hours_per_run).
rem Just double-click again to continue - finished work is never redone.
rem Keep the laptop plugged in. Safe to close this window.

cd /d "%~dp0"
title FYP - LLM jobs (stops by itself after max 3 h)
".venv\Scripts\python.exe" run_llm_unattended.py %*
echo.
echo Finished or paused. Log: results\processed\llm_run.log
pause
