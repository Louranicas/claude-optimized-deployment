"""
Communication MCP servers for the CODE project.

Enterprise messaging and alert management with multi-channel support.
"""

from src.mcp.communication.slack_server import SlackNotificationMCPServer

# Backward compatibility aliases
CommunicationHubMCP = SlackNotificationMCPServer
SlackNotificationMCP = SlackNotificationMCPServer

__all__ = ["SlackNotificationMCPServer", "CommunicationHubMCP", "SlackNotificationMCP"]