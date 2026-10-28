# Mealie MCP Server

[![Build and Push Docker Image](https://github.com/mdlopresti/mealie-mcp/actions/workflows/docker.yml/badge.svg)](https://github.com/mdlopresti/mealie-mcp/actions/workflows/docker.yml)
[![Test](https://github.com/mdlopresti/mealie-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/mdlopresti/mealie-mcp/actions/workflows/test.yml)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that enables AI assistants to interact with [Mealie](https://mealie.io/) for recipe management, meal planning, and shopping lists.

## Features

### Tools (31 total)

**Recipes**
- `mealie_recipes_search` - Search recipes by name, tags, or categories
- `mealie_recipes_get` - Get full recipe details including ingredients and instructions
- `mealie_recipes_list` - List all recipes with pagination
- `mealie_recipes_create` - Create a new recipe
- `mealie_recipes_create_from_url` - Import recipe by scraping a URL
- `mealie_recipes_update` - Update an existing recipe
- `mealie_recipes_update_structured_ingredients` - Update recipe with structured ingredients from parser
- `mealie_recipes_delete` - Delete a recipe

**Meal Planning**
- `mealie_mealplans_list` - List meal plans for a date range
- `mealie_mealplans_today` - Get today's meals
- `mealie_mealplans_get` - Get specific meal plan entry
- `mealie_mealplans_get_date` - Get meals for a specific date
- `mealie_mealplans_create` - Create meal plan entry
- `mealie_mealplans_update` - Update meal plan entry
- `mealie_mealplans_delete` - Delete meal plan entry
- `mealie_mealplans_random` - Get random meal suggestion

**Shopping Lists**
- `mealie_shopping_lists_list` - List all shopping lists
- `mealie_shopping_lists_get` - Get shopping list with items
- `mealie_shopping_lists_create` - Create new shopping list
- `mealie_shopping_lists_delete` - Delete shopping list
- `mealie_shopping_items_add` - Add item to list
- `mealie_shopping_items_add_bulk` - Add multiple items at once
- `mealie_shopping_items_check` - Mark item checked/unchecked
- `mealie_shopping_items_delete` - Remove item from list
- `mealie_shopping_add_recipe` - Add recipe ingredients to list
- `mealie_shopping_generate_from_mealplan` - Generate shopping list from meal plan
- `mealie_shopping_clear_checked` - Clear all checked items

**Ingredient Parsing**
- `mealie_parser_ingredient` - Parse single ingredient string to structured format
- `mealie_parser_ingredients_batch` - Parse multiple ingredient strings at once

### Resources

- `recipes://list` - Browse all recipes
- `recipes://{slug}` - View specific recipe
- `mealplans://current` - Current week's meal plan
- `mealplans://today` - Today's meals
- `mealplans://{date}` - Specific date's meals
- `shopping://lists` - All shopping lists
- `shopping://{list_id}` - Specific shopping list

## Prerequisites

- Docker (or Podman)
- A running Mealie instance
- Mealie API token

## Quick Start

### 1. Get the Docker Image

**Option A: Pull from GitHub Container Registry (recommended)**
```bash
docker pull ghcr.io/mdlopresti/mealie-mcp:latest
```

**Option B: Build from source**
```bash
git clone https://github.com/mdlopresti/mealie-mcp.git
cd mealie-mcp
docker build -t mealie-mcp:latest .
```

### 2. Get Your API Token

1. Log into your Mealie instance
2. Go to **User Settings** (click your name in sidebar)
3. Navigate to **API Tokens**
4. Create a new token (e.g., "MCP Server")
5. Copy the token immediately (it won't be shown again)

### 3. Configure Claude Code

Add to `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "mealie": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "MEALIE_URL=https://your-mealie-instance.com",
        "-e", "MEALIE_API_TOKEN=your-api-token-here",
        "ghcr.io/mdlopresti/mealie-mcp:latest"
      ]
    }
  }
}
```

Then add `mealie` to your `~/.claude/settings.json`:

```json
{
  "allowedMcpServers": [
    { "serverName": "mealie" }
  ]
}
```

### 4. Test the Connection

Restart Claude Code and try:
```
Can you search for recipes in Mealie?
```

## Usage Examples

### Clearing Optional Fields

To clear an optional field (remove its value), pass the special sentinel value `"__CLEAR__"`:

```python
# Remove recipe association from a meal plan entry
mealie_mealplans_update(
    mealplan_id="abc-123",
    recipe_id="__CLEAR__"
)

# Clear the title from an entry
mealie_mealplans_update(
    mealplan_id="abc-123",
    title="__CLEAR__"
)

# Clear the text/notes from an entry
mealie_mealplans_update(
    mealplan_id="abc-123",
    text="__CLEAR__"
)

# Clear multiple fields at once
mealie_mealplans_update(
    mealplan_id="abc-123",
    recipe_id="__CLEAR__",
    title="__CLEAR__",
    text="__CLEAR__"
)
```

To leave a field unchanged, simply omit it from the call:

```python
# Update only the date, preserving all other fields
mealie_mealplans_update(
    mealplan_id="abc-123",
    meal_date="2025-12-25"
)
```

## Development

### Local Development (without Docker)

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export MEALIE_URL=https://your-mealie-instance.com
export MEALIE_API_TOKEN=your-api-token

# Run server
python -m src.server
```

### Hosting over HTTP (remote agents)

By default the server uses stdio. To host it over the network, set `MCP_TRANSPORT=http` and a secret `MCP_AUTH_TOKEN`. The server refuses to start in HTTP mode without `MCP_AUTH_TOKEN` and/or `MCP_PUBLIC_URL` (OAuth, see below), and every request must be authenticated. A shared token is sent as the `Authorization: Bearer <token>`.

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `MCP_AUTH_TOKEN` | – | Shared bearer token (acts with the server's `MEALIE_API_TOKEN`); generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `MCP_PUBLIC_URL` | – | Enables OAuth; the public HTTPS URL of this server, e.g. `https://mcp.example.com` |
| `MCP_DATA_DIR` | `/data` in Docker | Where OAuth clients, tokens and the encryption key are stored (in-memory if unset) |
| `MCP_SECRET_KEY` | generated | Optional encryption secret for stored Mealie tokens; otherwise a key file is created in `MCP_DATA_DIR` |
| `MCP_HOST` | `0.0.0.0` | Bind address |
| `MCP_PORT` | `8000` | Port (endpoint is `/mcp`) |

```bash
docker run -d --restart=unless-stopped -p 8000:8000 \
  -e MCP_TRANSPORT=http -e MCP_AUTH_TOKEN=... \
  -e MEALIE_URL=https://your-mealie-instance.com -e MEALIE_API_TOKEN=... \
  ghcr.io/mdlopresti/mealie-mcp:latest
```

Put it behind a reverse proxy with HTTPS (Caddy, nginx, Cloudflare Tunnel); a bearer token over plain HTTP can be sniffed. VS Code client config (`.vscode/mcp.json`):

```json
{
  "inputs": [{ "type": "promptString", "id": "mealie-token", "description": "Mealie MCP token", "password": true }],
  "servers": {
    "mealie": {
      "type": "http",
      "url": "https://mcp.example.com/mcp",
      "headers": { "Authorization": "Bearer ${input:mealie-token}" }
    }
  }
}
```

### OAuth sign-in with Mealie accounts

Clients that cannot send a custom header (ChatGPT, claude.ai, other hosted agents) connect with OAuth 2.1. Set `MCP_PUBLIC_URL` and the server acts as its own authorization server: the client registers itself, the user is sent to a sign-in page hosted by this server, and logs in with their **Mealie username and password**. No third-party identity provider is needed, and Mealie is the user list.

- The password is only forwarded to Mealie to get a short-lived JWT, which is used once to create a long-lived Mealie API token for that user. Neither is stored in clear text: the API token is encrypted at rest and tokens issued to clients are stored hashed.
- Every request then runs with **that user's own Mealie permissions**, not the shared `MEALIE_API_TOKEN`.
- Access tokens last 1 hour; refresh tokens last 30 days and rotate on use. Revoking a grant deletes the Mealie API token it created (you can also see and delete them under *User Settings → API Tokens* in Mealie).
- Wrong passwords are throttled (5 attempts per sign-in and 5 per username per 15 minutes).
- `MCP_AUTH_TOKEN` can be set as well, so header-capable clients such as VS Code keep working alongside OAuth.
- Users who can only sign in to Mealie via OIDC (no password) cannot use this.

```bash
docker run -d --restart=unless-stopped -p 8000:8000 -v mealie-mcp-data:/data \
  -e MCP_TRANSPORT=http -e MCP_PUBLIC_URL=https://mcp.example.com \
  -e MEALIE_URL=http://mealie:9000 \
  ghcr.io/mdlopresti/mealie-mcp:latest
```

Mount a volume at `/data` (and make it writable by the container user) so users stay signed in across restarts. The server must be reachable at `MCP_PUBLIC_URL` over HTTPS, since clients discover the OAuth endpoints (`/.well-known/oauth-authorization-server`, `/authorize`, `/token`, `/register`, `/login`) from there; forward all paths, not just `/mcp`. Then add the server URL (`https://mcp.example.com/mcp`) in the client and choose OAuth.

### Running Tests

**Unit/Integration Tests** (mock API, always run):
```bash
# Run all tests except E2E
pytest -m "not e2e"

# Run all tests with coverage
pytest --cov=src --cov-report=term-missing
```

**End-to-End Tests** (optional):

E2E tests validate against a real Mealie instance. Two modes are supported:

**Docker E2E Tests** (recommended - isolated environment):
```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run Docker E2E tests
pytest tests/e2e/test_docker_e2e.py -v

# These tests:
# - Start a containerized Mealie instance automatically
# - Run tests in isolated environment
# - Clean up containers and data after tests
# - Require Docker/Podman to be running
```

**Live Instance E2E Tests** (test against existing server):
```bash
# Set required environment variables
export MEALIE_E2E_URL="https://your-mealie-instance.com"
export MEALIE_E2E_TOKEN="your-test-api-token"

# Run E2E tests against live instance
pytest -m e2e

# These tests are skipped if environment variables are not set
```

See [tests/e2e/README.md](tests/e2e/README.md) for detailed E2E testing documentation.

Note: Live instance E2E tests create and delete test resources. Use a test/development instance, not production!

### Project Structure

```
mealie-mcp/
├── Dockerfile           # Container definition
├── requirements.txt     # Python dependencies
├── build.sh            # Build helper script
└── src/
    ├── server.py       # MCP server entry point
    ├── client.py       # Mealie API client
    ├── tools/          # MCP tool implementations
    │   ├── recipes.py
    │   ├── mealplans.py
    │   ├── shopping.py
    │   └── parser.py
    └── resources/      # MCP resource implementations
        ├── recipes.py
        ├── mealplans.py
        └── shopping.py
```

## Security

- **Never commit API tokens** - Use environment variables
- The API token has full access to your Mealie account
- Consider creating a dedicated Mealie user for the MCP server

## Requirements

- Python 3.12+
- Mealie v1.0+ (tested with v3.6.1)

## License

MIT

## Contributing

Contributions welcome! Please open an issue or PR.

## Related

- [Mealie](https://mealie.io/) - Self-hosted recipe manager
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification
- [FastMCP](https://github.com/jlowin/fastmcp) - Python MCP framework
