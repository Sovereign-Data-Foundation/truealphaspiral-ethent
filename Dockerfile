# Use a secure, deterministic base image
FROM python:3.11-slim

# Set environment variables for immutability and provenance
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TAS_SOVEREIGN_MODE=strict

WORKDIR /opt/truealphaspiral

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt pytest

# Copy the core architecture
COPY . .

# (Optional) If you want to pull the drift detection logic from tas_pythonetics
# RUN git clone https://github.com/TrueAlpha-spiral/TrueAlpha-spiral.git /opt/tas_pythonetics

# The entrypoint forces the container to prove its integrity upon spin-up
# It will run the manifesto tests (and drift tests if included)
ENTRYPOINT ["pytest", "-v", "tests/test_manifesto.py"]
# Add "tests/" to run all tests, or specify the drift test path as well
