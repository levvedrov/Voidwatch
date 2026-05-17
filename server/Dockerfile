FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir psycopg2-binary

COPY backend/ ./
RUN mkdir -p /app/data /app/models

EXPOSE 8000

CMD ["python", "main.py"]
