FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Create non-root user
RUN useradd -m -u 1000 app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY ndr_checker/ ndr_checker/

# Ensure output directory exists and is writable by the app user
RUN mkdir -p output && chown -R app:app /app

# Switch to non-root user
USER app

# Set entrypoint to allow flexible CLI arguments
ENTRYPOINT ["python", "-m", "ndr_checker"]
