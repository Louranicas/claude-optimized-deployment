"""
DevOps and System Automation MCP servers for CODE project.

Implements Azure DevOps, Windows automation, and other DevOps-focused MCP servers
that integrate with the existing MCP framework.
"""

from __future__ import annotations
import os
import asyncio
import aiohttp
import platform
import json
import base64
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
import logging

from .protocols import MCPTool, MCPToolParameter, MCPServerInfo, MCPCapabilities, MCPError
from .servers import MCPServer

logger = logging.getLogger(__name__)


class AzureDevOpsMCPServer(MCPServer):
    """
    Azure DevOps MCP Server for CODE project.
    
    Provides Azure DevOps integration for CI/CD pipeline automation,
    work item management, and repository operations.
    """
    
    def __init__(self, organization: Optional[str] = None, personal_access_token: Optional[str] = None):
        """
        Initialize Azure DevOps MCP Server.
        
        Args:
            organization: Azure DevOps organization name
            personal_access_token: Personal Access Token for authentication
        """
        self.organization = organization or os.getenv("AZURE_DEVOPS_ORGANIZATION")
        self.pat = personal_access_token or os.getenv("AZURE_DEVOPS_TOKEN")
        self.base_url = f"https://dev.azure.com/{self.organization}" if self.organization else None
        self.session: Optional[aiohttp.ClientSession] = None
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for Azure DevOps API."""
        if not self.pat:
            raise MCPError(-32000, "Azure DevOps Personal Access Token is required")
        
        credentials = base64.b64encode(f":{self.pat}".encode()).decode()
        return {
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    
    def get_server_info(self) -> MCPServerInfo:
        """Get Azure DevOps server information."""
        return MCPServerInfo(
            name="azure-devops",
            version="1.0.0",
            description="Azure DevOps integration for CODE project CI/CD and project management",
            capabilities=MCPCapabilities(
                tools=True,
                resources=False,
                prompts=False,
                experimental={
                    "pipeline_automation": True,
                    "work_item_management": True,
                    "repository_operations": True,
                    "build_monitoring": True
                }
            )
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get available Azure DevOps tools."""
        return [
            MCPTool(
                name="list_projects",
                description="List Azure DevOps projects",
                parameters=[]
            ),
            MCPTool(
                name="list_pipelines",
                description="List build/release pipelines",
                parameters=[
                    MCPToolParameter(
                        name="project",
                        type="string",
                        description="Project name",
                        required=True
                    )
                ]
            ),
            MCPTool(
                name="trigger_pipeline",
                description="Trigger a build/release pipeline",
                parameters=[
                    MCPToolParameter(
                        name="project",
                        type="string",
                        description="Project name",
                        required=True
                    ),
                    MCPToolParameter(
                        name="pipeline_id",
                        type="integer",
                        description="Pipeline ID to trigger",
                        required=True
                    ),
                    MCPToolParameter(
                        name="branch",
                        type="string",
                        description="Source branch",
                        required=False,
                        default="main"
                    )
                ]
            ),
            MCPTool(
                name="get_pipeline_runs",
                description="Get pipeline run history",
                parameters=[
                    MCPToolParameter(
                        name="project",
                        type="string",
                        description="Project name",
                        required=True
                    ),
                    MCPToolParameter(
                        name="pipeline_id",
                        type="integer",
                        description="Pipeline ID",
                        required=True
                    ),
                    MCPToolParameter(
                        name="top",
                        type="integer",
                        description="Number of runs to retrieve",
                        required=False,
                        default=10
                    )
                ]
            ),
            MCPTool(
                name="create_work_item",
                description="Create a work item (bug, task, user story)",
                parameters=[
                    MCPToolParameter(
                        name="project",
                        type="string",
                        description="Project name",
                        required=True
                    ),
                    MCPToolParameter(
                        name="work_item_type",
                        type="string",
                        description="Work item type",
                        required=True,
                        enum=["Bug", "Task", "User Story", "Feature"]
                    ),
                    MCPToolParameter(
                        name="title",
                        type="string",
                        description="Work item title",
                        required=True
                    ),
                    MCPToolParameter(
                        name="description",
                        type="string",
                        description="Work item description",
                        required=False
                    ),
                    MCPToolParameter(
                        name="assigned_to",
                        type="string",
                        description="Assignee email",
                        required=False
                    )
                ]
            ),
            MCPTool(
                name="get_work_items",
                description="Query work items",
                parameters=[
                    MCPToolParameter(
                        name="project",
                        type="string",
                        description="Project name",
                        required=True
                    ),
                    MCPToolParameter(
                        name="wiql",
                        type="string",
                        description="Work Item Query Language (WIQL) query",
                        required=False
                    ),
                    MCPToolParameter(
                        name="assigned_to",
                        type="string",
                        description="Filter by assignee",
                        required=False
                    ),
                    MCPToolParameter(
                        name="state",
                        type="string",
                        description="Filter by state",
                        required=False
                    )
                ]
            ),
            MCPTool(
                name="create_pull_request",
                description="Create a pull request",
                parameters=[
                    MCPToolParameter(
                        name="project",
                        type="string",
                        description="Project name",
                        required=True
                    ),
                    MCPToolParameter(
                        name="repository",
                        type="string",
                        description="Repository name",
                        required=True
                    ),
                    MCPToolParameter(
                        name="source_branch",
                        type="string",
                        description="Source branch",
                        required=True
                    ),
                    MCPToolParameter(
                        name="target_branch",
                        type="string",
                        description="Target branch",
                        required=True
                    ),
                    MCPToolParameter(
                        name="title",
                        type="string",
                        description="Pull request title",
                        required=True
                    ),
                    MCPToolParameter(
                        name="description",
                        type="string",
                        description="Pull request description",
                        required=False
                    )
                ]
            )
        ]
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute an Azure DevOps tool."""
        if not self.organization or not self.pat:
            raise MCPError(-32000, "Azure DevOps organization and PAT must be configured")
        
        if not self.session:
            self.session = aiohttp.ClientSession()
        
        try:
            if tool_name == "list_projects":
                return await self._list_projects()
            elif tool_name == "list_pipelines":
                return await self._list_pipelines(**arguments)
            elif tool_name == "trigger_pipeline":
                return await self._trigger_pipeline(**arguments)
            elif tool_name == "get_pipeline_runs":
                return await self._get_pipeline_runs(**arguments)
            elif tool_name == "create_work_item":
                return await self._create_work_item(**arguments)
            elif tool_name == "get_work_items":
                return await self._get_work_items(**arguments)
            elif tool_name == "create_pull_request":
                return await self._create_pull_request(**arguments)
            else:
                raise MCPError(-32601, f"Unknown tool: {tool_name}")
        except Exception as e:
            logger.error(f"Error calling Azure DevOps tool {tool_name}: {e}")
            raise
    
    async def _list_projects(self) -> Dict[str, Any]:
        """List Azure DevOps projects."""
        url = f"{self.base_url}/_apis/projects?api-version=7.0"
        
        async with self.session.get(url, headers=self._get_auth_headers()) as response:
            if response.status != 200:
                raise MCPError(-32000, f"Failed to list projects: {response.status}")
            
            data = await response.json()
            
            projects = []
            for project in data.get("value", []):
                projects.append({
                    "id": project.get("id"),
                    "name": project.get("name"),
                    "description": project.get("description"),
                    "state": project.get("state"),
                    "visibility": project.get("visibility")
                })
            
            return {
                "projects": projects,
                "total": len(projects)
            }
    
    async def _list_pipelines(self, project: str) -> Dict[str, Any]:
        """List build pipelines."""
        url = f"{self.base_url}/{project}/_apis/pipelines?api-version=7.0"
        
        async with self.session.get(url, headers=self._get_auth_headers()) as response:
            if response.status != 200:
                raise MCPError(-32000, f"Failed to list pipelines: {response.status}")
            
            data = await response.json()
            
            pipelines = []
            for pipeline in data.get("value", []):
                pipelines.append({
                    "id": pipeline.get("id"),
                    "name": pipeline.get("name"),
                    "folder": pipeline.get("folder"),
                    "revision": pipeline.get("revision")
                })
            
            return {
                "project": project,
                "pipelines": pipelines,
                "total": len(pipelines)
            }
    
    async def _trigger_pipeline(
        self,
        project: str,
        pipeline_id: int,
        branch: str = "main"
    ) -> Dict[str, Any]:
        """Trigger a pipeline run."""
        url = f"{self.base_url}/{project}/_apis/pipelines/{pipeline_id}/runs?api-version=7.0"
        
        payload = {
            "resources": {
                "repositories": {
                    "self": {
                        "refName": f"refs/heads/{branch}"
                    }
                }
            }
        }
        
        async with self.session.post(
            url,
            headers=self._get_auth_headers(),
            json=payload
        ) as response:
            if response.status not in [200, 201]:
                raise MCPError(-32000, f"Failed to trigger pipeline: {response.status}")
            
            data = await response.json()
            
            return {
                "project": project,
                "pipeline_id": pipeline_id,
                "run_id": data.get("id"),
                "state": data.get("state"),
                "branch": branch,
                "url": data.get("url")
            }
    
    async def _get_pipeline_runs(
        self,
        project: str,
        pipeline_id: int,
        top: int = 10
    ) -> Dict[str, Any]:
        """Get pipeline run history."""
        url = f"{self.base_url}/{project}/_apis/pipelines/{pipeline_id}/runs?api-version=7.0&$top={top}"
        
        async with self.session.get(url, headers=self._get_auth_headers()) as response:
            if response.status != 200:
                raise MCPError(-32000, f"Failed to get pipeline runs: {response.status}")
            
            data = await response.json()
            
            runs = []
            for run in data.get("value", []):
                runs.append({
                    "id": run.get("id"),
                    "name": run.get("name"),
                    "state": run.get("state"),
                    "result": run.get("result"),
                    "created_date": run.get("createdDate"),
                    "finished_date": run.get("finishedDate"),
                    "url": run.get("url")
                })
            
            return {
                "project": project,
                "pipeline_id": pipeline_id,
                "runs": runs,
                "total": len(runs)
            }
    
    async def _create_work_item(
        self,
        project: str,
        work_item_type: str,
        title: str,
        description: Optional[str] = None,
        assigned_to: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a work item."""
        url = f"{self.base_url}/{project}/_apis/wit/workitems/${work_item_type}?api-version=7.0"
        
        operations = [
            {
                "op": "add",
                "path": "/fields/System.Title",
                "value": title
            }
        ]
        
        if description:
            operations.append({
                "op": "add",
                "path": "/fields/System.Description",
                "value": description
            })
        
        if assigned_to:
            operations.append({
                "op": "add",
                "path": "/fields/System.AssignedTo",
                "value": assigned_to
            })
        
        headers = self._get_auth_headers()
        headers["Content-Type"] = "application/json-patch+json"
        
        async with self.session.post(url, headers=headers, json=operations) as response:
            if response.status not in [200, 201]:
                raise MCPError(-32000, f"Failed to create work item: {response.status}")
            
            data = await response.json()
            
            return {
                "project": project,
                "work_item_id": data.get("id"),
                "title": title,
                "type": work_item_type,
                "state": data.get("fields", {}).get("System.State"),
                "url": data.get("url")
            }
    
    async def _get_work_items(
        self,
        project: str,
        wiql: Optional[str] = None,
        assigned_to: Optional[str] = None,
        state: Optional[str] = None
    ) -> Dict[str, Any]:
        """Query work items."""
        if not wiql:
            # Build default query
            conditions = [f"[System.TeamProject] = '{project}'"]
            
            if assigned_to:
                conditions.append(f"[System.AssignedTo] = '{assigned_to}'")
            
            if state:
                conditions.append(f"[System.State] = '{state}'")
            
            wiql = f"SELECT [System.Id], [System.Title], [System.State] FROM WorkItems WHERE {' AND '.join(conditions)}"
        
        url = f"{self.base_url}/{project}/_apis/wit/wiql?api-version=7.0"
        
        payload = {"query": wiql}
        
        async with self.session.post(
            url,
            headers=self._get_auth_headers(),
            json=payload
        ) as response:
            if response.status != 200:
                raise MCPError(-32000, f"Failed to query work items: {response.status}")
            
            data = await response.json()
            
            work_items = []
            for item in data.get("workItems", []):
                work_items.append({
                    "id": item.get("id"),
                    "url": item.get("url")
                })
            
            return {
                "project": project,
                "query": wiql,
                "work_items": work_items,
                "total": len(work_items)
            }
    
    async def _create_pull_request(
        self,
        project: str,
        repository: str,
        source_branch: str,
        target_branch: str,
        title: str,
        description: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a pull request."""
        url = f"{self.base_url}/{project}/_apis/git/repositories/{repository}/pullrequests?api-version=7.0"
        
        payload = {
            "sourceRefName": f"refs/heads/{source_branch}",
            "targetRefName": f"refs/heads/{target_branch}",
            "title": title
        }
        
        if description:
            payload["description"] = description
        
        async with self.session.post(
            url,
            headers=self._get_auth_headers(),
            json=payload
        ) as response:
            if response.status not in [200, 201]:
                raise MCPError(-32000, f"Failed to create pull request: {response.status}")
            
            data = await response.json()
            
            return {
                "project": project,
                "repository": repository,
                "pull_request_id": data.get("pullRequestId"),
                "title": title,
                "source_branch": source_branch,
                "target_branch": target_branch,
                "status": data.get("status"),
                "url": data.get("url")
            }
    
    async def close(self):
        """Close the session."""
        if self.session:
            await self.session.close()
            self.session = None


class WindowsSystemMCPServer(MCPServer):
    """
    Windows System MCP Server for CODE project.
    
    Provides Windows system automation capabilities for infrastructure
    deployment and testing on Windows environments.
    """
    
    def __init__(self):
        """Initialize Windows System MCP Server."""
        self.is_windows = platform.system().lower() == "windows"
    
    def get_server_info(self) -> MCPServerInfo:
        """Get Windows System server information."""
        return MCPServerInfo(
            name="windows-system",
            version="1.0.0",
            description="Windows system automation for CODE project deployment",
            capabilities=MCPCapabilities(
                tools=True,
                resources=False,
                prompts=False,
                experimental={
                    "windows_automation": True,
                    "powershell_execution": True,
                    "service_management": True,
                    "registry_operations": True
                }
            )
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get available Windows System tools."""
        return [
            MCPTool(
                name="powershell_command",
                description="Execute PowerShell commands for Windows automation",
                parameters=[
                    MCPToolParameter(
                        name="command",
                        type="string",
                        description="PowerShell command to execute",
                        required=True
                    ),
                    MCPToolParameter(
                        name="execution_policy",
                        type="string",
                        description="PowerShell execution policy",
                        required=False,
                        enum=["Bypass", "RemoteSigned", "Unrestricted"],
                        default="RemoteSigned"
                    )
                ]
            ),
            MCPTool(
                name="windows_service",
                description="Manage Windows services",
                parameters=[
                    MCPToolParameter(
                        name="action",
                        type="string",
                        description="Service action",
                        required=True,
                        enum=["start", "stop", "restart", "status", "list"]
                    ),
                    MCPToolParameter(
                        name="service_name",
                        type="string",
                        description="Windows service name",
                        required=False
                    )
                ]
            ),
            MCPTool(
                name="check_windows_features",
                description="Check Windows features and capabilities",
                parameters=[
                    MCPToolParameter(
                        name="feature_name",
                        type="string",
                        description="Specific Windows feature to check",
                        required=False
                    )
                ]
            ),
            MCPTool(
                name="windows_environment",
                description="Manage Windows environment variables",
                parameters=[
                    MCPToolParameter(
                        name="action",
                        type="string",
                        description="Environment action",
                        required=True,
                        enum=["get", "set", "list", "delete"]
                    ),
                    MCPToolParameter(
                        name="variable_name",
                        type="string",
                        description="Environment variable name",
                        required=False
                    ),
                    MCPToolParameter(
                        name="variable_value",
                        type="string",
                        description="Environment variable value",
                        required=False
                    ),
                    MCPToolParameter(
                        name="scope",
                        type="string",
                        description="Variable scope",
                        required=False,
                        enum=["Process", "User", "Machine"],
                        default="Process"
                    )
                ]
            ),
            MCPTool(
                name="windows_network",
                description="Windows network configuration and testing",
                parameters=[
                    MCPToolParameter(
                        name="action",
                        type="string",
                        description="Network action",
                        required=True,
                        enum=["ping", "telnet", "netstat", "ipconfig"]
                    ),
                    MCPToolParameter(
                        name="target",
                        type="string",
                        description="Target host or port",
                        required=False
                    ),
                    MCPToolParameter(
                        name="port",
                        type="integer",
                        description="Port number for telnet test",
                        required=False
                    )
                ]
            )
        ]
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute a Windows System tool."""
        if not self.is_windows:
            # Provide limited functionality on non-Windows systems
            logger.warning(f"Windows tool {tool_name} called on non-Windows system")
        
        try:
            if tool_name == "powershell_command":
                return await self._powershell_command(**arguments)
            elif tool_name == "windows_service":
                return await self._windows_service(**arguments)
            elif tool_name == "check_windows_features":
                return await self._check_windows_features(**arguments)
            elif tool_name == "windows_environment":
                return await self._windows_environment(**arguments)
            elif tool_name == "windows_network":
                return await self._windows_network(**arguments)
            else:
                raise MCPError(-32601, f"Unknown tool: {tool_name}")
        except Exception as e:
            logger.error(f"Error calling Windows System tool {tool_name}: {e}")
            raise
    
    async def _powershell_command(
        self,
        command: str,
        execution_policy: str = "RemoteSigned"
    ) -> Dict[str, Any]:
        """Execute PowerShell command."""
        if self.is_windows:
            cmd = f'powershell.exe -ExecutionPolicy {execution_policy} -Command "{command}"'
        else:
            # Use pwsh on non-Windows systems if available
            cmd = f'pwsh -ExecutionPolicy {execution_policy} -Command "{command}"'
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                "command": command,
                "execution_policy": execution_policy,
                "exit_code": process.returncode,
                "stdout": stdout.decode('utf-8', errors='replace'),
                "stderr": stderr.decode('utf-8', errors='replace'),
                "success": process.returncode == 0
            }
        except Exception as e:
            raise MCPError(-32000, f"PowerShell command failed: {str(e)}")
    
    async def _windows_service(
        self,
        action: str,
        service_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Manage Windows services."""
        if action == "list":
            command = "Get-Service | Select-Object Name, Status, StartType | ConvertTo-Json"
        elif action == "status" and service_name:
            command = f"Get-Service -Name '{service_name}' | ConvertTo-Json"
        elif action in ["start", "stop", "restart"] and service_name:
            if action == "restart":
                command = f"Restart-Service -Name '{service_name}' -PassThru | ConvertTo-Json"
            else:
                command = f"{action.capitalize()}-Service -Name '{service_name}' -PassThru | ConvertTo-Json"
        else:
            raise MCPError(-32602, f"Invalid service action or missing service name")
        
        result = await self._powershell_command(command)
        
        try:
            if result["success"] and result["stdout"]:
                service_data = json.loads(result["stdout"])
                result["service_info"] = service_data
        except json.JSONDecodeError:
            pass
        
        return {
            "action": action,
            "service_name": service_name,
            **result
        }
    
    async def _check_windows_features(
        self,
        feature_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Check Windows features."""
        if feature_name:
            command = f"Get-WindowsOptionalFeature -Online -FeatureName '{feature_name}' | ConvertTo-Json"
        else:
            command = "Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' } | Select-Object FeatureName, State | ConvertTo-Json"
        
        result = await self._powershell_command(command)
        
        try:
            if result["success"] and result["stdout"]:
                feature_data = json.loads(result["stdout"])
                result["features"] = feature_data
        except json.JSONDecodeError:
            pass
        
        return {
            "feature_name": feature_name,
            **result
        }
    
    async def _windows_environment(
        self,
        action: str,
        variable_name: Optional[str] = None,
        variable_value: Optional[str] = None,
        scope: str = "Process"
    ) -> Dict[str, Any]:
        """Manage Windows environment variables."""
        if action == "list":
            command = "Get-ChildItem Env: | ConvertTo-Json"
        elif action == "get" and variable_name:
            command = f"[Environment]::GetEnvironmentVariable('{variable_name}', '{scope}')"
        elif action == "set" and variable_name and variable_value:
            command = f"[Environment]::SetEnvironmentVariable('{variable_name}', '{variable_value}', '{scope}')"
        elif action == "delete" and variable_name:
            command = f"[Environment]::SetEnvironmentVariable('{variable_name}', $null, '{scope}')"
        else:
            raise MCPError(-32602, f"Invalid environment action or missing parameters")
        
        result = await self._powershell_command(command)
        
        return {
            "action": action,
            "variable_name": variable_name,
            "variable_value": variable_value,
            "scope": scope,
            **result
        }
    
    async def _windows_network(
        self,
        action: str,
        target: Optional[str] = None,
        port: Optional[int] = None
    ) -> Dict[str, Any]:
        """Windows network operations."""
        if action == "ping" and target:
            command = f"Test-Connection -ComputerName '{target}' -Count 4 | ConvertTo-Json"
        elif action == "telnet" and target and port:
            command = f"Test-NetConnection -ComputerName '{target}' -Port {port} | ConvertTo-Json"
        elif action == "netstat":
            command = "Get-NetTCPConnection | ConvertTo-Json"
        elif action == "ipconfig":
            command = "Get-NetIPConfiguration | ConvertTo-Json"
        else:
            raise MCPError(-32602, f"Invalid network action or missing parameters")
        
        result = await self._powershell_command(command)
        
        try:
            if result["success"] and result["stdout"]:
                network_data = json.loads(result["stdout"])
                result["network_info"] = network_data
        except json.JSONDecodeError:
            pass
        
        return {
            "action": action,
            "target": target,
            "port": port,
            **result
        }