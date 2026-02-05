FROM python:3.12-slim

LABEL maintainer="KSeF Invoice Reader"
LABEL description="Docker container for fetching invoices from KSeF (Krajowy System e-Faktur)"

# Install system dependencies required for lxml, cryptography and PDF fonts
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2-dev \
    libxslt1-dev \
    libffi-dev \
    libssl-dev \
    gcc \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY ksef_faktury_list.py .

# Create directories for certificates and output
RUN mkdir -p /certs /output

# Set entrypoint
ENTRYPOINT ["python", "ksef_faktury_list.py"]

# Default help command
CMD ["--help"]
