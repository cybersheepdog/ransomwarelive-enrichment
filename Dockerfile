FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /opt/connector

COPY src/requirements.txt ./requirements.txt
# libmagic1 is a runtime dependency of python-magic (pulled in by pycti); it
# must remain in the final image, so it is NOT purged.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 \
    && pip install --no-cache-dir -r requirements.txt \
    && rm -rf /var/lib/apt/lists/*

COPY src/ ./src/
COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
