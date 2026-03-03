FROM python:3.10-slim

WORKDIR /app
RUN pip install --no-cache-dir --upgrade pip

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY services/common /app/services/common
COPY services/scorer /app/services/scorer

EXPOSE 8000
CMD ["python", "services/scorer/score_anomalies_ml.py"]
