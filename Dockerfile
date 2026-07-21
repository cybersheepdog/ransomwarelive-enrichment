FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /opt/connector

COPY src/requirements.txt ./requirements.txt
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y git && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY src/ ./src/
COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
