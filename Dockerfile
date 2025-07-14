FROM python:3.11-slim

WORKDIR /app

# Install build dependencies for cryptography if needed
RUN apt-get update && apt-get install -y build-essential libffi-dev libssl-dev

# Install pycose from GitHub master (latest fixes) and cryptography
RUN pip install --no-cache-dir git+https://github.com/TimothyClaeys/pycose.git@master cryptography

COPY cose_signer.py .

ENTRYPOINT ["python", "cose_signer.py"]
