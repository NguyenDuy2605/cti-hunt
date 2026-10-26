@echo off
set PYTHONIOENCODING=utf-8
echo Dang khoi dong Giao dien CTI to Hunt (N6 Demo)...
.venv\Scripts\python.exe -m streamlit run app\streamlit_app.py --server.address localhost
