# Base container image for all CAIRN services per context.md §11
FROM python:3.12-slim

# Avoid writing .pyc files to container rootfs and buffer stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Create non-root user 'cairn' (UID/GID 10001) per context.md §7.2
RUN groupadd -g 10001 cairn && \
    useradd -u 10001 -g cairn -s /bin/bash -m cairn && \
    mkdir -p /run/cairn /tmp/cairn && \
    chown -R cairn:cairn /run/cairn /tmp/cairn /app

# Install dependencies from pinned requirements.lock
COPY requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir -r /app/requirements.lock

# Copy project source and install cairn package
COPY pyproject.toml /app/pyproject.toml
COPY src/ /app/src/
COPY data/ /app/data/
RUN pip install --no-cache-dir --no-deps -e /app

USER 10001:10001

CMD ["python", "-c", "import time; time.sleep(86400)"]
