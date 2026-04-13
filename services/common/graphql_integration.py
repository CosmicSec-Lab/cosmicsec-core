"""
CosmicSec GraphQL Integration Layer
Provides GraphQL API alongside REST API with Ariadne
"""

from typing import Any, Dict, List, Optional
from datetime import datetime

# GraphQL Schema Definition (as string for flexibility)
GRAPHQL_SCHEMA = """
type Query {
    scan(id: ID!): Scan
    scans(limit: Int, offset: Int, status: ScanStatus): [Scan!]!
    finding(id: ID!): Finding
    findings(scanId: ID!, severity: Severity): [Finding!]!
    agent(id: ID!): Agent
    agents(status: AgentStatus): [Agent!]!
    dashboard: Dashboard!
}

type Mutation {
    createScan(input: CreateScanInput!): ScanResult!
    updateScan(id: ID!, input: UpdateScanInput!): ScanResult!
    cancelScan(id: ID!): ScanResult!
    deleteScan(id: ID!): DeleteResult!
    dismissFinding(id: ID!): FindingResult!
}

type Subscription {
    scanProgress(scanId: ID!): ScanEvent!
    findingDiscovered(scanId: ID!): Finding!
}

# Core Types
type Scan {
    id: ID!
    target: String!
    status: ScanStatus!
    type: ScanType!
    findings: [Finding!]!
    agentId: ID
    createdAt: DateTime!
    startedAt: DateTime
    completedAt: DateTime
    progress: Int!
    errorMessage: String
    _runtime: RuntimeInfo!
}

type Finding {
    id: ID!
    scanId: ID!
    title: String!
    severity: Severity!
    description: String!
    evidence: String
    tool: String!
    target: String!
    source: String!
    createdAt: DateTime!
    dismissed: Boolean!
}

type Agent {
    id: ID!
    hostname: String!
    platform: String!
    status: AgentStatus!
    tools: [ToolInfo!]!
    lastSeen: DateTime!
    version: String!
}

type ToolInfo {
    name: String!
    path: String!
    version: String!
    capabilities: [String!]!
}

type Dashboard {
    securityScore: Int!
    totalScans: Int!
    criticalFindings: Int!
    activeAgents: Int!
    openBugReports: Int!
    compliancePct: Float!
    recentActivity: [ActivityEvent!]!
    moduleHealth: [ModuleHealth!]!
}

type ActivityEvent {
    id: ID!
    type: String!
    severity: Severity!
    description: String!
    timestamp: DateTime!
    source: String!
}

type ModuleHealth {
    name: String!
    status: HealthStatus!
    lastChecked: DateTime!
    latency: Int!
}

type RuntimeInfo {
    mode: String!
    degraded: Boolean!
    traceId: String!
    latencyMs: Float!
}

type ScanResult {
    success: Boolean!
    scan: Scan
    error: String
}

type FindingResult {
    success: Boolean!
    finding: Finding
    error: String
}

type DeleteResult {
    success: Boolean!
    deletedId: ID
    error: String
}

# Input Types
input CreateScanInput {
    target: String!
    scanType: ScanType!
    tools: [String!]
    priority: Priority
}

input UpdateScanInput {
    status: ScanStatus
    notes: String
}

# Enums
enum ScanStatus {
    PENDING
    RUNNING
    COMPLETED
    FAILED
    CANCELLED
}

enum ScanType {
    NETWORK
    WEB
    APPLICATION
    INFRASTRUCTURE
    CLOUD
}

enum Severity {
    CRITICAL
    HIGH
    MEDIUM
    LOW
    INFO
}

enum Priority {
    LOW
    MEDIUM
    HIGH
    URGENT
}

enum AgentStatus {
    ONLINE
    IDLE
    BUSY
    OFFLINE
}

enum HealthStatus {
    HEALTHY
    DEGRADED
    UNAVAILABLE
}

scalar DateTime
"""


class GraphQLResolvers:
    """Collection of resolver functions for GraphQL queries."""
    
    def __init__(self, db_session=None, service_clients: Dict[str, Any] = None):
        self.db = db_session
        self.services = service_clients or {}
    
    async def resolve_scan(self, obj, info, id: str):
        """Resolve single scan query."""
        try:
            # From scan service
            service = self.services.get("scan_service")
            if service:
                return await service.get_scan(id)
        except Exception as e:
            raise ValueError(f"Failed to fetch scan: {str(e)}")
        return None
    
    async def resolve_scans(
        self,
        obj,
        info,
        limit: int = 10,
        offset: int = 0,
        status: Optional[str] = None,
    ):
        """Resolve scans query with pagination and filtering."""
        try:
            service = self.services.get("scan_service")
            if service:
                filters = {}
                if status:
                    filters["status"] = status
                
                return await service.list_scans(
                    limit=limit,
                    offset=offset,
                    **filters,
                )
        except Exception as e:
            raise ValueError(f"Failed to fetch scans: {str(e)}")
        return []
    
    async def resolve_findings(
        self,
        obj,
        info,
        scan_id: str,
        severity: Optional[str] = None,
    ):
        """Resolve findings for a scan."""
        try:
            service = self.services.get("scan_service")
            if service:
                filters = {"scan_id": scan_id}
                if severity:
                    filters["severity"] = severity
                
                return await service.list_findings(**filters)
        except Exception as e:
            raise ValueError(f"Failed to fetch findings: {str(e)}")
        return []
    
    async def resolve_dashboard(self, obj, info):
        """Resolve dashboard overview."""
        try:
            service = self.services.get("api_gateway")
            if service:
                return await service.get_dashboard_overview()
        except Exception as e:
            raise ValueError(f"Failed to fetch dashboard: {str(e)}")
        
        return {
            "security_score": 0,
            "total_scans": 0,
            "critical_findings": 0,
            "active_agents": 0,
            "open_bug_reports": 0,
            "compliance_pct": 0.0,
        }
    
    async def resolve_agents(
        self,
        obj,
        info,
        status: Optional[str] = None,
    ):
        """Resolve agents with optional status filter."""
        try:
            service = self.services.get("agent_relay")
            if service:
                filters = {}
                if status:
                    filters["status"] = status
                
                return await service.list_agents(**filters)
        except Exception as e:
            raise ValueError(f"Failed to fetch agents: {str(e)}")
        return []
    
    async def resolve_create_scan(self, obj, info, input: Dict[str, Any]):
        """Resolve createScan mutation."""
        try:
            service = self.services.get("scan_service")
            if service:
                return {
                    "success": True,
                    "scan": await service.create_scan(**input),
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }
    
    async def resolve_cancel_scan(self, obj, info, id: str):
        """Resolve cancelScan mutation."""
        try:
            service = self.services.get("scan_service")
            if service:
                result = await service.cancel_scan(id)
                return {
                    "success": result,
                    "scan": await service.get_scan(id) if result else None,
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }


class GraphQLIntegration:
    """Integration helper for adding GraphQL to FastAPI."""
    
    @staticmethod
    def get_schema() -> str:
        """Get the GraphQL schema string."""
        return GRAPHQL_SCHEMA
    
    @staticmethod
    def setup_resolvers(
        query_resolver,
        mutation_resolver=None,
        subscription_resolver=None,
    ) -> Dict[str, Any]:
        """Setup resolver mappings for Ariadne."""
        resolvers = {
            "Query": {
                "scan": query_resolver.resolve_scan,
                "scans": query_resolver.resolve_scans,
                "finding": query_resolver.resolve_finding,
                "findings": query_resolver.resolve_findings,
                "agent": query_resolver.resolve_agent,
                "agents": query_resolver.resolve_agents,
                "dashboard": query_resolver.resolve_dashboard,
            },
        }
        
        if mutation_resolver:
            resolvers["Mutation"] = {
                "createScan": mutation_resolver.resolve_create_scan,
                "updateScan": mutation_resolver.resolve_update_scan,
                "cancelScan": mutation_resolver.resolve_cancel_scan,
                "deleteScan": mutation_resolver.resolve_delete_scan,
                "dismissFinding": mutation_resolver.resolve_dismiss_finding,
            }
        
        return resolvers


# Example usage in FastAPI:
"""
from ariadne import make_executable_schema, QueryType, graphql_sync
from ariadne.asgi import GraphQL

# In your FastAPI app setup:

schema_def = GraphQLIntegration.get_schema()
resolvers = GraphQLResolvers(db=db_session, service_clients=services)

executable_schema = make_executable_schema(schema_def)

# Add GraphQL endpoint
app.add_route(
    "/graphql",
    GraphQL(executable_schema),
    methods=["GET", "POST"]
)
"""
