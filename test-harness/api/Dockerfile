FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ARG SERVICE_VERSION=local
ARG VCS_REVISION=unknown
ENV SERVICE_VERSION=${SERVICE_VERSION} \
    VCS_REVISION=${VCS_REVISION}
LABEL org.opencontainers.image.version=${SERVICE_VERSION} \
      org.opencontainers.image.revision=${VCS_REVISION}

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]