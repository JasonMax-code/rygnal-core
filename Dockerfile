FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src:/app

WORKDIR /app

COPY requirements-dev.txt pyproject.toml ./

RUN python -m pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements-dev.txt

COPY . .

CMD ["python", "-m", "demo.run_demo"]
