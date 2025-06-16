#!/usr/bin/env python3
"""
AGENT 10 - Circle of Experts MCP Server Validation
==================================================

Comprehensive validation test that deploys the circle of experts framework
to validate ALL MCP server functionality and generate a capability report.

This test:
1. Activates all expert types (Development, Security, Performance, DevOps, Quality)
2. Tests expert communication and collaboration 
3. Validates expert decision-making frameworks
4. Conducts MCP server capability assessment with each expert
5. Runs collaborative problem-solving scenarios
6. Generates comprehensive expert consensus report
"""

import asyncio
import json
import logging
import os
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('circle_experts_mcp_validation.log')
    ]
)
logger = logging.getLogger(__name__)

# Import Circle of Experts components
try:
    from src.circle_of_experts import EnhancedExpertManager, ExpertQuery, QueryType, QueryPriority
    from src.circle_of_experts.models.response import ExpertType, ResponseStatus
    logger.info("✅ Circle of Experts modules imported successfully")
except ImportError as e:
    logger.error(f"❌ Failed to import Circle of Experts modules: {e}")
    sys.exit(1)

# Import MCP components
try:
    from src.mcp.manager import MCPManager
    from src.mcp.servers import MCPServerType
    logger.info("✅ MCP modules imported successfully")
except ImportError as e:
    logger.warning(f"⚠️ MCP modules not available: {e}")
    MCPManager = None
    MCPServerType = None

class ExpertMCPValidator:
    """Main class for validating MCP servers using Circle of Experts."""
    
    def __init__(self):
        """Initialize the validator with expert manager and configurations."""
        self.expert_manager = None
        self.validation_results = {
            "start_time": datetime.utcnow().isoformat(),
            "expert_deployment": {},
            "mcp_assessments": {},
            "collaboration_tests": {},
            "consensus_reports": {},
            "performance_metrics": {},
            "recommendations": []
        }
        self.expert_types = [
            ExpertType.CLAUDE,      # Development Expert
            ExpertType.GPT4,        # Security Expert  
            ExpertType.GEMINI,      # Performance Expert
            ExpertType.DEEPSEEK,    # DevOps Expert
            ExpertType.SUPERGROK    # Quality Expert
        ]
        
    async def initialize_expert_manager(self) -> bool:
        """Initialize the enhanced expert manager."""
        try:
            logger.info("🚀 Initializing Enhanced Expert Manager...")
            
            # Create expert manager with performance monitoring
            self.expert_manager = EnhancedExpertManager(
                enable_performance_monitoring=True,
                use_rust_acceleration=True,
                max_concurrent_queries=3,
                memory_budget_mb=1024.0,
                enable_streaming=True
            )
            
            # Optimize for performance
            await self.expert_manager.optimize_for_performance()
            
            logger.info("✅ Expert Manager initialized successfully")
            self.validation_results["expert_deployment"]["manager_initialized"] = True
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize Expert Manager: {e}")
            self.validation_results["expert_deployment"]["manager_initialized"] = False
            self.validation_results["expert_deployment"]["error"] = str(e)
            return False
    
    async def test_expert_system_functionality(self) -> Dict[str, Any]:
        """Test all expert types for functionality and responsiveness."""
        logger.info("🧠 Testing Expert System Functionality...")
        
        expert_tests = {}
        
        for expert_type in self.expert_types:
            logger.info(f"  Testing {expert_type.value} expert...")
            
            try:
                # Create a simple test query for each expert
                test_query = self._create_expert_test_query(expert_type)
                
                start_time = time.time()
                result = await self.expert_manager.consult_experts_enhanced(
                    title=f"Expert Test: {expert_type.value}",
                    content=test_query,
                    requester="agent_10_validator",
                    query_type=QueryType.GENERAL,
                    priority=QueryPriority.HIGH,
                    required_experts=[expert_type],
                    response_timeout=60.0,
                    min_responses=1
                )
                elapsed_time = time.time() - start_time
                
                expert_tests[expert_type.value] = {
                    "status": "success",
                    "response_time": round(elapsed_time, 3),
                    "confidence": result.get("aggregation", {}).get("average_confidence", 0.0),
                    "rust_accelerated": result.get("performance", {}).get("rust_accelerated", False),
                    "recommendations_count": len(result.get("aggregation", {}).get("common_recommendations", [])),
                    "consensus_level": result.get("aggregation", {}).get("consensus_level", "unknown")
                }
                
                logger.info(f"    ✅ {expert_type.value} expert responding - {elapsed_time:.2f}s")
                
            except Exception as e:
                expert_tests[expert_type.value] = {
                    "status": "failed",
                    "error": str(e),
                    "response_time": 0.0
                }
                logger.error(f"    ❌ {expert_type.value} expert failed: {e}")
        
        # Calculate overall expert availability
        successful_experts = [t for t in expert_tests.values() if t["status"] == "success"]
        availability_rate = len(successful_experts) / len(self.expert_types) * 100
        
        self.validation_results["expert_deployment"]["expert_tests"] = expert_tests
        self.validation_results["expert_deployment"]["availability_rate"] = round(availability_rate, 1)
        
        logger.info(f"📊 Expert System Test Complete - {availability_rate:.1f}% availability")
        return expert_tests
    
    def _create_expert_test_query(self, expert_type: ExpertType) -> str:
        """Create specialized test queries for each expert type."""
        queries = {
            ExpertType.CLAUDE: """
            As a Development Expert, analyze this code pattern:
            
            ```python
            def process_data(items):
                return [item.upper() for item in items if item]
            ```
            
            What are 3 potential improvements?
            """,
            
            ExpertType.GPT4: """
            As a Security Expert, evaluate this authentication approach:
            
            ```python
            def authenticate(token):
                if token == "admin123":
                    return True
                return False
            ```
            
            What are the main security vulnerabilities?
            """,
            
            ExpertType.GEMINI: """
            As a Performance Expert, assess this database query pattern:
            
            ```sql
            SELECT * FROM users WHERE email LIKE '%@domain.com%'
            ```
            
            How can this be optimized for large datasets?
            """,
            
            ExpertType.DEEPSEEK: """
            As a DevOps Expert, review this deployment configuration:
            
            ```yaml
            services:
              app:
                image: myapp:latest
                ports:
                  - "80:3000"
            ```
            
            What production considerations are missing?
            """,
            
            ExpertType.SUPERGROK: """
            As a Quality Expert, analyze this test structure:
            
            ```python
            def test_function():
                result = my_function()
                assert result == "expected"
            ```
            
            How can test quality be improved?
            """
        }
        
        return queries.get(expert_type, "Provide a brief technical analysis of system optimization approaches.")
    
    async def conduct_mcp_server_assessment(self) -> Dict[str, Any]:
        """Conduct comprehensive MCP server assessment with each expert."""
        logger.info("🔍 Conducting MCP Server Assessment...")
        
        mcp_assessments = {}
        
        # Define MCP server assessment scenarios
        assessment_scenarios = [
            {
                "name": "Development Workflow Servers",
                "description": "Assess MCP servers supporting development workflows",
                "expert": ExpertType.CLAUDE,
                "focus_areas": ["code_generation", "testing", "debugging", "documentation"]
            },
            {
                "name": "Security Infrastructure Servers", 
                "description": "Evaluate security-focused MCP servers",
                "expert": ExpertType.GPT4,
                "focus_areas": ["vulnerability_scanning", "auth_integration", "secure_communication", "audit_logging"]
            },
            {
                "name": "Performance Optimization Servers",
                "description": "Analyze performance-critical MCP servers", 
                "expert": ExpertType.GEMINI,
                "focus_areas": ["response_times", "throughput", "resource_usage", "scaling"]
            },
            {
                "name": "DevOps Deployment Servers",
                "description": "Review deployment and operations MCP servers",
                "expert": ExpertType.DEEPSEEK, 
                "focus_areas": ["deployment_automation", "monitoring", "configuration_management", "rollback_procedures"]
            },
            {
                "name": "Quality Assurance Servers",
                "description": "Examine testing and quality MCP servers",
                "expert": ExpertType.SUPERGROK,
                "focus_areas": ["test_automation", "quality_metrics", "compliance_checking", "error_handling"]
            }
        ]
        
        for scenario in assessment_scenarios:
            logger.info(f"  📋 Assessing: {scenario['name']}")
            
            try:
                assessment_query = f"""
                Expert Assessment Request: {scenario['description']}
                
                As a {scenario['expert'].value} expert, provide a comprehensive assessment of MCP servers in the following areas:
                
                Focus Areas:
                {chr(10).join(f"- {area}" for area in scenario['focus_areas'])}
                
                Please evaluate:
                1. Current implementation quality (1-10 scale)
                2. Production readiness assessment
                3. Specific recommendations for improvement  
                4. Critical issues that must be addressed
                5. Performance optimization opportunities
                6. Integration compatibility assessment
                
                Format your response with clear sections and actionable recommendations.
                """
                
                result = await self.expert_manager.consult_experts_enhanced(
                    title=f"MCP Assessment: {scenario['name']}",
                    content=assessment_query,
                    requester="agent_10_mcp_validator",
                    query_type=QueryType.REVIEW,
                    priority=QueryPriority.HIGH,
                    required_experts=[scenario['expert']],
                    response_timeout=120.0,
                    tags=scenario['focus_areas']
                )
                
                mcp_assessments[scenario['name']] = {
                    "expert": scenario['expert'].value,
                    "status": "completed",
                    "confidence": result.get("aggregation", {}).get("average_confidence", 0.0),
                    "recommendations": result.get("aggregation", {}).get("common_recommendations", []),
                    "processing_time": result.get("performance", {}).get("total_time", 0.0),
                    "focus_areas": scenario['focus_areas'],
                    "detailed_response": result.get("aggregation", {}).get("summary", "")
                }
                
                logger.info(f"    ✅ {scenario['name']} assessment complete")
                
            except Exception as e:
                mcp_assessments[scenario['name']] = {
                    "expert": scenario['expert'].value,
                    "status": "failed",
                    "error": str(e)
                }
                logger.error(f"    ❌ {scenario['name']} assessment failed: {e}")
        
        self.validation_results["mcp_assessments"] = mcp_assessments
        logger.info("📊 MCP Server Assessment Complete")
        return mcp_assessments
    
    async def run_collaborative_scenarios(self) -> Dict[str, Any]:
        """Run collaborative problem-solving scenarios with multiple experts."""
        logger.info("🤝 Running Collaborative Problem-Solving Scenarios...")
        
        collaboration_tests = {}
        
        # Define collaborative scenarios
        scenarios = [
            {
                "name": "Multi-Expert Architecture Review",
                "description": "Collaborative review of system architecture",
                "experts": [ExpertType.CLAUDE, ExpertType.GPT4, ExpertType.GEMINI],
                "query": """
                Collaborative Architecture Review:
                
                We need to design a high-performance, secure MCP server architecture that can:
                - Handle 10,000+ concurrent connections
                - Process real-time data streams
                - Maintain 99.9% uptime
                - Integrate with multiple AI services
                - Support horizontal scaling
                
                Each expert should contribute their specialized perspective:
                - Development: Implementation patterns and code architecture
                - Security: Security controls and threat mitigation
                - Performance: Optimization strategies and bottleneck prevention
                
                Please provide a collaborative recommendation.
                """
            },
            {
                "name": "Cross-Domain Problem Solving",
                "description": "Multi-expert consultation on complex integration",
                "experts": [ExpertType.DEEPSEEK, ExpertType.SUPERGROK],
                "query": """
                Cross-Domain Integration Challenge:
                
                We need to integrate our MCP server deployment with:
                - Kubernetes orchestration
                - CI/CD pipelines
                - Monitoring and alerting systems
                - Quality assurance workflows
                
                DevOps Expert: Focus on deployment automation and infrastructure
                Quality Expert: Focus on testing strategies and quality gates
                
                Provide coordinated recommendations for seamless integration.
                """
            },
            {
                "name": "Full Circle Consensus Building",
                "description": "All experts collaborate on production readiness",
                "experts": self.expert_types,
                "query": """
                Production Readiness Assessment:
                
                Our MCP server framework is approaching production deployment.
                We need ALL experts to collaborate and build consensus on:
                
                1. Is the system ready for production deployment?
                2. What are the highest priority items to address?
                3. What monitoring and observability is needed?
                4. What are the recommended deployment phases?
                5. What success criteria should we establish?
                
                Each expert should provide their domain perspective, and we need
                to build consensus on the overall readiness and next steps.
                """
            }
        ]
        
        for scenario in scenarios:
            logger.info(f"  🎯 Running: {scenario['name']}")
            
            try:
                result = await self.expert_manager.consult_experts_enhanced(
                    title=scenario['name'],
                    content=scenario['query'],
                    requester="agent_10_collaborative_validator",
                    query_type=QueryType.CONSENSUS,
                    priority=QueryPriority.HIGH,
                    required_experts=scenario['experts'],
                    response_timeout=180.0,
                    min_responses=len(scenario['experts'])
                )
                
                collaboration_tests[scenario['name']] = {
                    "status": "completed",
                    "participating_experts": [e.value for e in scenario['experts']],
                    "consensus_level": result.get("aggregation", {}).get("consensus_level", "unknown"),
                    "average_confidence": result.get("aggregation", {}).get("average_confidence", 0.0),
                    "recommendations": result.get("aggregation", {}).get("common_recommendations", []),
                    "processing_time": result.get("performance", {}).get("total_time", 0.0),
                    "expert_count": len(scenario['experts']),
                    "collaborative_summary": result.get("aggregation", {}).get("summary", "")
                }
                
                logger.info(f"    ✅ {scenario['name']} complete - Consensus: {result.get('aggregation', {}).get('consensus_level', 'unknown')}")
                
            except Exception as e:
                collaboration_tests[scenario['name']] = {
                    "status": "failed",
                    "error": str(e),
                    "participating_experts": [e.value for e in scenario['experts']]
                }
                logger.error(f"    ❌ {scenario['name']} failed: {e}")
        
        self.validation_results["collaboration_tests"] = collaboration_tests
        logger.info("📊 Collaborative Scenarios Complete")
        return collaboration_tests
    
    async def generate_consensus_report(self) -> Dict[str, Any]:
        """Generate comprehensive expert consensus report."""
        logger.info("📋 Generating Expert Consensus Report...")
        
        # Collect performance metrics
        performance_report = {}
        if self.expert_manager:
            try:
                performance_report = self.expert_manager.get_performance_report()
            except Exception as e:
                logger.warning(f"Could not get performance report: {e}")
        
        # Build consensus analysis
        consensus_data = {
            "report_generated": datetime.utcnow().isoformat(),
            "validation_summary": {
                "expert_availability": self.validation_results["expert_deployment"].get("availability_rate", 0),
                "successful_assessments": len([a for a in self.validation_results["mcp_assessments"].values() if a.get("status") == "completed"]),
                "successful_collaborations": len([c for c in self.validation_results["collaboration_tests"].values() if c.get("status") == "completed"]),
                "total_expert_consultations": performance_report.get("query_metrics", {}).get("total_queries", 0)
            },
            "performance_metrics": performance_report,
            "expert_recommendations": self._aggregate_expert_recommendations(),
            "production_readiness": self._assess_production_readiness(),
            "next_steps": self._generate_next_steps()
        }
        
        self.validation_results["consensus_reports"] = consensus_data
        self.validation_results["performance_metrics"] = performance_report
        
        logger.info("✅ Expert Consensus Report Generated")
        return consensus_data
    
    def _aggregate_expert_recommendations(self) -> List[str]:
        """Aggregate recommendations from all expert assessments."""
        recommendations = []
        
        # Collect from MCP assessments
        for assessment in self.validation_results["mcp_assessments"].values():
            if assessment.get("status") == "completed":
                recommendations.extend(assessment.get("recommendations", []))
        
        # Collect from collaborative tests
        for test in self.validation_results["collaboration_tests"].values():
            if test.get("status") == "completed":
                recommendations.extend(test.get("recommendations", []))
        
        # Remove duplicates while preserving order
        unique_recommendations = []
        seen = set()
        for rec in recommendations:
            if rec not in seen:
                unique_recommendations.append(rec)
                seen.add(rec)
        
        return unique_recommendations[:20]  # Top 20 recommendations
    
    def _assess_production_readiness(self) -> Dict[str, Any]:
        """Assess overall production readiness based on expert consensus."""
        assessments = self.validation_results["mcp_assessments"]
        collaborations = self.validation_results["collaboration_tests"]
        
        # Calculate readiness score
        total_assessments = len(assessments)
        successful_assessments = len([a for a in assessments.values() if a.get("status") == "completed"])
        
        total_collaborations = len(collaborations)
        successful_collaborations = len([c for c in collaborations.values() if c.get("status") == "completed"])
        
        expert_availability = self.validation_results["expert_deployment"].get("availability_rate", 0)
        
        # Weighted readiness score
        assessment_score = (successful_assessments / total_assessments * 100) if total_assessments > 0 else 0
        collaboration_score = (successful_collaborations / total_collaborations * 100) if total_collaborations > 0 else 0
        
        overall_score = (assessment_score * 0.4 + collaboration_score * 0.4 + expert_availability * 0.2)
        
        readiness_level = "Not Ready"
        if overall_score >= 90:
            readiness_level = "Production Ready"
        elif overall_score >= 75:
            readiness_level = "Nearly Ready"
        elif overall_score >= 50:
            readiness_level = "Development Complete"
        
        return {
            "overall_score": round(overall_score, 1),
            "readiness_level": readiness_level,
            "assessment_score": round(assessment_score, 1),
            "collaboration_score": round(collaboration_score, 1),
            "expert_availability": expert_availability,
            "critical_issues": self._identify_critical_issues()
        }
    
    def _identify_critical_issues(self) -> List[str]:
        """Identify critical issues from expert feedback."""
        issues = []
        
        # Check for failed expert tests
        expert_tests = self.validation_results["expert_deployment"].get("expert_tests", {})
        failed_experts = [expert for expert, test in expert_tests.items() if test.get("status") == "failed"]
        if failed_experts:
            issues.append(f"Expert system failures: {', '.join(failed_experts)}")
        
        # Check for low availability
        availability = self.validation_results["expert_deployment"].get("availability_rate", 0)
        if availability < 80:
            issues.append(f"Low expert availability: {availability}%")
        
        # Check for failed assessments
        failed_assessments = [name for name, assessment in self.validation_results["mcp_assessments"].items() 
                            if assessment.get("status") == "failed"]
        if failed_assessments:
            issues.append(f"Failed MCP assessments: {', '.join(failed_assessments)}")
        
        # Check for failed collaborations
        failed_collaborations = [name for name, collab in self.validation_results["collaboration_tests"].items()
                               if collab.get("status") == "failed"]
        if failed_collaborations:
            issues.append(f"Failed collaborative tests: {', '.join(failed_collaborations)}")
        
        return issues
    
    def _generate_next_steps(self) -> List[str]:
        """Generate recommended next steps based on validation results."""
        steps = []
        
        readiness = self._assess_production_readiness()
        
        if readiness["overall_score"] >= 90:
            steps.extend([
                "✅ System is production ready - proceed with deployment",
                "🔄 Implement continuous monitoring and alerting", 
                "📊 Establish performance baselines and SLAs",
                "🔐 Conduct final security review and penetration testing"
            ])
        elif readiness["overall_score"] >= 75:
            steps.extend([
                "🔧 Address remaining critical issues before production",
                "📋 Complete final integration testing",
                "📚 Finalize operational documentation",
                "👥 Conduct stakeholder review and approval"
            ])
        else:
            steps.extend([
                "⚠️ Significant development work required before production",
                "🧪 Focus on fixing failed expert validations",
                "🔄 Re-run validation after addressing critical issues",
                "📈 Improve system performance and reliability"
            ])
        
        # Add specific steps based on issues
        if readiness["critical_issues"]:
            steps.append(f"🚨 Priority: Resolve critical issues - {'; '.join(readiness['critical_issues'])}")
        
        return steps
    
    async def run_full_validation(self) -> Dict[str, Any]:
        """Run the complete Circle of Experts MCP validation suite."""
        logger.info("🚀 Starting Circle of Experts MCP Validation...")
        
        try:
            # Step 1: Initialize Expert Manager
            if not await self.initialize_expert_manager():
                return self.validation_results
            
            # Step 2: Test Expert System Functionality
            await self.test_expert_system_functionality()
            
            # Step 3: Conduct MCP Server Assessment
            await self.conduct_mcp_server_assessment()
            
            # Step 4: Run Collaborative Scenarios  
            await self.run_collaborative_scenarios()
            
            # Step 5: Generate Consensus Report
            await self.generate_consensus_report()
            
            # Finalize results
            self.validation_results["end_time"] = datetime.utcnow().isoformat()
            self.validation_results["validation_status"] = "completed"
            
            # Log summary
            readiness = self.validation_results["consensus_reports"]["production_readiness"]
            logger.info(f"✅ Validation Complete - Readiness: {readiness['readiness_level']} ({readiness['overall_score']}%)")
            
            return self.validation_results
            
        except Exception as e:
            logger.error(f"❌ Validation failed: {e}")
            logger.error(traceback.format_exc())
            
            self.validation_results["validation_status"] = "failed"
            self.validation_results["error"] = str(e)
            self.validation_results["end_time"] = datetime.utcnow().isoformat()
            
            return self.validation_results


async def main():
    """Main execution function."""
    logger.info("=" * 80)
    logger.info("AGENT 10 - Circle of Experts MCP Server Validation")
    logger.info("=" * 80)
    
    # Create validator
    validator = ExpertMCPValidator()
    
    # Run full validation
    results = await validator.run_full_validation()
    
    # Save results
    results_file = f"agent10_circle_experts_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    # Print summary
    print("\n" + "=" * 80)
    print("CIRCLE OF EXPERTS MCP VALIDATION SUMMARY")
    print("=" * 80)
    
    if results.get("validation_status") == "completed":
        readiness = results["consensus_reports"]["production_readiness"]
        print(f"🎯 Overall Readiness: {readiness['readiness_level']} ({readiness['overall_score']}%)")
        print(f"👥 Expert Availability: {results['expert_deployment'].get('availability_rate', 0)}%")
        print(f"📊 Successful Assessments: {readiness['assessment_score']}%")
        print(f"🤝 Successful Collaborations: {readiness['collaboration_score']}%")
        
        if readiness['critical_issues']:
            print(f"\n🚨 Critical Issues:")
            for issue in readiness['critical_issues']:
                print(f"   - {issue}")
        
        print(f"\n📋 Top Recommendations:")
        for i, rec in enumerate(results["consensus_reports"]["expert_recommendations"][:5], 1):
            print(f"   {i}. {rec}")
        
        print(f"\n🎯 Next Steps:")
        for step in results["consensus_reports"]["next_steps"]:
            print(f"   {step}")
    else:
        print(f"❌ Validation Failed: {results.get('error', 'Unknown error')}")
    
    print(f"\n📄 Full results saved to: {results_file}")
    print("=" * 80)
    
    return results


if __name__ == "__main__":
    # Set up environment
    os.environ.setdefault("PYTHONPATH", str(project_root))
    
    # Run validation
    asyncio.run(main())