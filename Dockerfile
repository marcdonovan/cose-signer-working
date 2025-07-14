FROM python:3.11-slim

WORKDIR /app

COPY cose_signer.py .
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "cose_signer.py"]
