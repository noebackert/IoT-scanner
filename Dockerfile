FROM python:3.10-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y \
    net-tools iputils-ping nmap arp-scan \
    postgresql-client \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
# Copy the rest of the application
COPY . .

# Expose port 5000 for Flask
EXPOSE 5000

CMD ["python", "app.py"]
