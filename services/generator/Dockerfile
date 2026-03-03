FROM python:3.10-slim

WORKDIR /app
RUN pip install --no-cache-dir --upgrade pip

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY services/common /app/services/common
COPY services/generator /app/services/generator

CMD ["python", "services/generator/generate_telemetry.py"]
