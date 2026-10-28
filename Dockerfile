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
# MCP_TRANSPORT=http plus MCP_AUTH_TOKEN and/or MCP_PUBLIC_URL (OAuth), and
# publish port 8000 (MCP_PORT). OAuth state (clients, tokens, encryption key)
# lives in /data; mount a volume there so sign-ins survive restarts.
# MEALIE_URL and MEALIE_API_TOKEN must be provided at runtime
RUN mkdir -p /data && chmod 777 /data
ENV MCP_DATA_DIR=/data
VOLUME /data
EXPOSE 8000

ENTRYPOINT ["python", "-m", "src.server"]
