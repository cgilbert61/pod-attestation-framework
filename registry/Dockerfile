FROM python:3.11-slim

WORKDIR /app
RUN pip install --no-cache-dir \
    "cryptography>=41.0.0" \
    "jsonschema>=4.20.0" \
    "pydantic>=2.5.0" \
    "fastapi>=0.109.0" \
    "uvicorn>=0.27.0" \
    "sqlalchemy>=2.0.25" \
    "httpx>=0.26.0" \
    "pyjwt>=2.8.0" \
    "openpyxl>=3.1.2" \
    "psycopg2-binary>=2.9.9"

COPY pyproject.toml LICENSE ./
COPY schemas ./schemas
COPY registry ./registry
COPY engine ./engine
COPY snapshot ./snapshot
RUN pip install --no-cache-dir --no-deps -e .

VOLUME ["/var/lib/pod/keys", "/var/lib/pod/data"]
ENV POD_KEY_DIR=/var/lib/pod/keys
EXPOSE 8080

CMD ["uvicorn", "registry.api:create_registry_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
