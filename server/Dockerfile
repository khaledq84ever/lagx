FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY relay.py .
EXPOSE 51820/udp
ENV LAGX_PORT=51820 LAGX_LOG=INFO
ENTRYPOINT ["python", "relay.py"]
