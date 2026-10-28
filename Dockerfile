# Mealie MCP Server
# FastMCP-based Model Context Protocol server for Mealie integration

FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/

# Default transport is stdio (stdin/stdout). For hosting over HTTP set
# MCP_TRANSPORT=http and MCP_AUTH_TOKEN, and publish port 8000 (MCP_PORT).
# MEALIE_URL and MEALIE_API_TOKEN must be provided at runtime
EXPOSE 8000

ENTRYPOINT ["python", "-m", "src.server"]
