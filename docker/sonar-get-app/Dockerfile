# Use a lightweight Python base image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Set the working directory
WORKDIR /app

# Copy project files
COPY . /app


# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose a directory for output files
VOLUME ["/opt/akvorado/config/"]

# Default command
CMD ["python", "/app/src/app-sonar-get.py"] 
