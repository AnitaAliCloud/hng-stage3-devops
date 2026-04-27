FROM python:3.11-slim

RUN addgroup --system appgroup && \
    adduser --system --ingroup appgroup appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appgroup . .

RUN mkdir -p /var/log/detector && \
    chown -R appuser:appgroup /var/log/detector

USER appuser

EXPOSE 8080

CMD ["python", "main.py"]