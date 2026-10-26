import sys
from streamlit.web import cli
if __name__ == '__main__':
    sys.argv = ["streamlit", "run", "src/cti_hunt/demo_app.py"]
    sys.exit(cli.main())
