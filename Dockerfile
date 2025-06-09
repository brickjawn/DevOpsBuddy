FROM python:3.11-slim

# Set labels for metadata
LABEL org.opencontainers.image.title="DevOps Buddy"
LABEL org.opencontainers.image.description="Automated DevSecOps Security Scanner"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.authors="DevOps Buddy Team <security@devopsbuddy.com>"
LABEL org.opencontainers.image.source="https://github.com/brickjawn/DevOpsBuddy"
LABEL org.opencontainers.image.licenses="MIT"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# Create app directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    gnupg \
    ca-certificates \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r scanner && \
    useradd -r -g scanner -m -u 1000 scanner && \
    chown -R scanner:scanner /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install the application
RUN pip install --no-cache-dir -e .

# Create necessary directories
RUN mkdir -p /app/reports /app/logs && \
    chown -R scanner:scanner /app/reports /app/logs

# Switch to non-root user
USER scanner

# Set up health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD devops-buddy --version || exit 1

# Expose port (if web interface is added later)
EXPOSE 8080

# Default command
ENTRYPOINT ["devops-buddy"]
CMD ["--help"]

# Volume for reports and configurations
VOLUME ["/app/reports", "/app/configs"] 