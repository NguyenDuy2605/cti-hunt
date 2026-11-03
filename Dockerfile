# cti-hunt HTTP API, phase 1 (six endpoints, no LLM calls).
#   docker compose up --build                                  # base image: technique lookup with BM25 only
#   EXTRAS=api,ingest,sigma,embed docker compose up --build    # adds hybrid retrieval (CPU PyTorch, much larger image)
# Data (ATT&CK, log sets, reports, SigmaHQ) is not baked into the image: mount the host data/ folder at /app/data.
FROM python:3.12-slim

ARG EXTRAS=api,ingest,sigma
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HOME=/models/hf

WORKDIR /app
RUN useradd --create-home --uid 10001 cti

# Embed variant: install the CPU build of PyTorch first; the default Linux wheel on PyPI pulls several GB of CUDA libraries.
RUN case ",${EXTRAS}," in *,embed,*) pip install "torch==2.15.0" --index-url https://download.pytorch.org/whl/cpu ;; esac

COPY pyproject.toml README.md ./
COPY src ./src
COPY configs ./configs
COPY prompts ./prompts
# Editable install so that the repository root (config.ROOT) is /app, where data/ is mounted.
RUN pip install -e ".[${EXTRAS}]" \
    && mkdir -p /app/data /models \
    && chown cti:cti /app/data /models

USER cti
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import sys, urllib.request; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status != 200)"
# Inside the container the server must listen on 0.0.0.0; docker-compose publishes the port on the host's 127.0.0.1 only.
CMD ["python", "-m", "cti_hunt", "api", "--host", "0.0.0.0", "--port", "8000"]
