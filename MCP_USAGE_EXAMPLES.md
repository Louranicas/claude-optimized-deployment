# MCP Server Usage Examples

This guide provides practical examples for using each configured MCP server in Claude Code.

## Table of Contents
1. [Filesystem Server](#filesystem-server)
2. [Brave Search Server](#brave-search-server)
3. [GitHub Server](#github-server)
4. [PostgreSQL Server](#postgresql-server)
5. [Memory Server](#memory-server)
6. [Slack Server](#slack-server)
7. [Puppeteer Server](#puppeteer-server)
8. [Desktop Commander](#desktop-commander)
9. [Git Server](#git-server)
10. [SQLite Server](#sqlite-server)
11. [Time Server](#time-server)
12. [Fetch Server](#fetch-server)

## Filesystem Server

The filesystem server provides safe file system access.

### Example Usage:
```
"Can you list all Python files in my project?"
"Read the contents of README.md"
"Create a new file called test.py with a hello world script"
"What's the directory structure of src/?"
```

### Capabilities:
- Read files and directories
- Create and modify files
- Search for files by pattern
- Get file metadata

## Brave Search Server

Web search capabilities using Brave Search API.

### Example Usage:
```
"Search for the latest DevOps trends in 2025"
"Find information about Kubernetes best practices"
"What are the current Python security vulnerabilities?"
"Search for MCP protocol documentation"
```

### Capabilities:
- Web search with current results
- News search
- Image search (if configured)
- Safe search filtering

## GitHub Server

Interact with GitHub repositories.

### Example Usage:
```
"List all open issues in this repository"
"Create a new issue about the bug in authentication"
"Show me recent pull requests"
"What are the latest commits?"
"Create a new branch called feature/new-api"
```

### Capabilities:
- Repository management
- Issue and PR operations
- Branch and commit operations
- GitHub Actions status

## PostgreSQL Server

Database operations on PostgreSQL.

### Example Usage:
```
"Show me all tables in the database"
"Query the users table"
"Insert a new record into the logs table"
"What's the schema of the products table?"
"Run: SELECT COUNT(*) FROM orders WHERE status='pending'"
```

### Capabilities:
- Execute SQL queries
- Schema inspection
- Data manipulation (INSERT, UPDATE, DELETE)
- Transaction support

## Memory Server

Persistent memory storage across sessions.

### Example Usage:
```
"Remember that the API key for service X is stored in .env"
"What did I tell you about the project architecture?"
"Store this configuration for later use"
"Recall our previous conversation about deployment"
```

### Capabilities:
- Store key-value pairs
- Retrieve stored information
- List all memories
- Delete specific memories

## Slack Server

Slack workspace integration.

### Example Usage:
```
"Post a message to #general channel saying the deployment is complete"
"What are the recent messages in #dev-team?"
"Send a DM to @john about the meeting"
"List all channels I have access to"
```

### Capabilities:
- Send messages to channels
- Read channel history
- Direct messages
- Channel management

## Puppeteer Server

Web automation and scraping.

### Example Usage:
```
"Take a screenshot of https://example.com"
"Extract all links from the documentation page"
"Fill out the contact form on the website"
"What's the current price on this product page?"
```

### Capabilities:
- Web scraping
- Screenshot generation
- Form automation
- JavaScript execution

## Desktop Commander

Desktop automation and control.

### Example Usage:
```
"Take a screenshot of my current screen"
"Open the terminal application"
"Show me running applications"
"Minimize all windows"
```

### Capabilities:
- Screenshot capture
- Application control
- Window management
- System information

## Git Server

Git repository operations.

### Example Usage:
```
"What's the current git status?"
"Commit all changes with message 'Fix authentication bug'"
"Show me the git log for the last week"
"Create a new branch called bugfix/memory-leak"
"What files have been modified?"
```

### Capabilities:
- Repository status
- Commit operations
- Branch management
- History inspection

## SQLite Server

SQLite database operations.

### Example Usage:
```
"Create a new table called tasks with id, title, and status columns"
"Insert a new task into the database"
"Query all incomplete tasks"
"Show me the database schema"
```

### Capabilities:
- Database creation
- Table operations
- Query execution
- Schema management

## Time Server

Time and date utilities.

### Example Usage:
```
"What time is it in Tokyo?"
"Convert 3pm EST to UTC"
"How many days until December 25th?"
"What day of the week was January 1, 2000?"
```

### Capabilities:
- Current time in any timezone
- Time zone conversion
- Date calculations
- Calendar operations

## Fetch Server

HTTP request capabilities.

### Example Usage:
```
"Fetch the API response from https://api.example.com/users"
"Make a POST request to the webhook URL with this JSON data"
"What are the headers returned by this endpoint?"
"Download the content from this URL"
```

### Capabilities:
- GET, POST, PUT, DELETE requests
- Custom headers
- JSON handling
- Response parsing

## Combining MCP Servers

You can combine multiple MCP servers for complex tasks:

### Example Workflows:

1. **Development Workflow**:
   ```
   "Search for best practices on authentication (Brave), 
    implement them in auth.py (Filesystem), 
    commit the changes (Git), 
    and create a PR (GitHub)"
   ```

2. **Data Pipeline**:
   ```
   "Fetch data from the API (Fetch),
    store it in PostgreSQL (Postgres),
    and notify the team on Slack (Slack)"
   ```

3. **Monitoring Workflow**:
   ```
   "Check the current time (Time),
    query database for errors in the last hour (Postgres),
    take a screenshot of the monitoring dashboard (Puppeteer),
    and post it to #ops channel (Slack)"
   ```

## Best Practices

1. **Be Specific**: Provide clear instructions for better results
2. **Chain Operations**: Combine servers for complex workflows
3. **Error Handling**: MCP servers will report errors clearly
4. **Security**: Be cautious with sensitive data and credentials
5. **Performance**: Some operations may take time (e.g., web scraping)

## Troubleshooting

If an MCP server isn't working:

1. Check configuration: `claude mcp`
2. Verify API keys are set correctly
3. Ensure required dependencies are installed
4. Check server logs for errors
5. Restart Claude Code after configuration changes

## Security Notes

- Filesystem access is restricted to configured directories
- Database operations should use parameterized queries
- API keys should be kept secure and not shared
- Be cautious with web automation on sensitive sites
- Review operations before executing destructive commands

---

For more details on configuration, see `MCP_SETUP_GUIDE.md`