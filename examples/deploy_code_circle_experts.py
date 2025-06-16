#!/usr/bin/env python3
"""
Circle of Experts + deploy-code Integration Example

Demonstrates how to use the Circle of Experts to generate optimal
deploy-code configurations for different deployment scenarios.
"""

import asyncio
import sys
import os
import json
import yaml
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.circle_of_experts import (
    ExpertManager,
    QueryType,
    QueryPriority,
    ExpertType
)


class DeployCodeExpertConsultation:
    """
    Uses Circle of Experts to generate optimal deploy-code configurations.
    """
    
    def __init__(self):
        self.expert_manager = None
        self.consultation_id = f"deploy_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
    async def initialize(self):
        """Initialize the Expert Manager."""
        print("🎓 Initializing Circle of Experts for deploy-code consultation")
        print("=" * 60)
        
        self.expert_manager = ExpertManager(
            credentials_path=os.getenv("GOOGLE_CREDENTIALS_PATH"),
            log_level="INFO"
        )
        
        return True
    
    async def consult_deployment_architecture(self, project_context: Dict[str, Any]) -> Dict[str, Any]:
        """Consult experts about optimal deployment architecture."""
        print("\n🏗️  Consulting experts about deployment architecture...")
        
        context_description = f"""
        Project Context:
        - Application Type: {project_context.get('app_type', 'Unknown')}
        - Expected Scale: {project_context.get('scale', 'Unknown')}
        - Technology Stack: {', '.join(project_context.get('tech_stack', []))}
        - Environment: {project_context.get('environment', 'Unknown')}
        - Budget Constraints: {project_context.get('budget', 'Unknown')}
        - Team Size: {project_context.get('team_size', 'Unknown')}
        - Compliance Requirements: {', '.join(project_context.get('compliance', []))}
        
        Question:
        Based on this project context, what would be the optimal deployment architecture?
        
        Please provide specific recommendations for:
        1. Target platform (Docker, Kubernetes, Cloud services)
        2. Scaling strategy (horizontal vs vertical)
        3. Security considerations
        4. Monitoring and observability setup
        5. CI/CD pipeline recommendations
        6. Infrastructure as Code approach
        
        Focus on practical, implementable solutions that balance performance,
        cost, and maintainability.
        """
        
        result = await self.expert_manager.consult_experts(
            title="Optimal Deployment Architecture Consultation",
            content=context_description,
            requester="deploy-code@system",
            query_type=QueryType.ARCHITECTURE,
            priority=QueryPriority.HIGH,
            tags=["deployment", "architecture", "infrastructure", "deploy-code"],
            min_experts=3,
            max_experts=5,
            expert_timeout=300.0
        )
        
        return result
    
    async def consult_configuration_optimization(self, deployment_type: str) -> Dict[str, Any]:
        """Consult experts about deploy-code configuration optimization."""
        print(f"\n⚙️  Consulting experts about {deployment_type} configuration...")
        
        optimization_query = f"""
        Deploy-code Configuration Optimization for {deployment_type.title()} Environment
        
        I need expert advice on optimizing a deploy-code configuration for a {deployment_type} environment.
        
        Key areas for optimization:
        1. Resource allocation and limits
        2. Health check configurations
        3. Security hardening settings
        4. Performance tuning parameters
        5. Backup and disaster recovery setup
        6. Monitoring and alerting configuration
        7. Network policies and service mesh integration
        8. Scaling policies and load balancing
        
        Please provide:
        - Specific configuration recommendations
        - Best practice patterns for {deployment_type}
        - Common pitfalls to avoid
        - Performance optimization techniques
        - Security hardening measures
        
        Consider modern cloud-native patterns and infrastructure as code principles.
        """
        
        result = await self.expert_manager.consult_experts(
            title=f"Deploy-code {deployment_type.title()} Configuration Optimization",
            content=optimization_query,
            requester="deploy-code@system",
            query_type=QueryType.OPTIMIZATION,
            priority=QueryPriority.MEDIUM,
            tags=["deploy-code", "configuration", deployment_type, "optimization"],
            min_experts=2,
            max_experts=4,
            expert_timeout=240.0
        )
        
        return result
    
    async def consult_security_hardening(self, config_path: str) -> Dict[str, Any]:
        """Consult experts about security hardening for deploy-code configs."""
        print("\n🔒 Consulting experts about security hardening...")
        
        # Read the configuration file if it exists
        config_content = ""
        if Path(config_path).exists():
            with open(config_path, 'r') as f:
                config_content = f.read()
        
        security_query = f"""
        Security Hardening for Deploy-code Configuration
        
        Current Configuration:
        ```yaml
        {config_content[:2000]}{'...' if len(config_content) > 2000 else ''}
        ```
        
        Please review this deploy-code configuration and provide security hardening recommendations:
        
        1. Container Security:
           - Base image security
           - Runtime security contexts
           - Capability restrictions
           - Read-only filesystems
        
        2. Network Security:
           - Network policies
           - Service mesh integration
           - TLS/mTLS configuration
           - Ingress security
        
        3. Authentication & Authorization:
           - RBAC policies
           - Service account configuration
           - Secret management
           - API authentication
        
        4. Compliance & Governance:
           - Security scanning integration
           - Audit logging
           - Policy enforcement
           - Compliance frameworks (SOC2, PCI-DSS, etc.)
        
        5. Monitoring & Incident Response:
           - Security monitoring
           - Alert configuration
           - Incident response automation
           - Forensics capabilities
        
        Please provide specific YAML configuration snippets and explain the security benefits.
        """
        
        result = await self.expert_manager.consult_experts(
            title="Deploy-code Security Hardening Consultation",
            content=security_query,
            requester="security@system",
            query_type=QueryType.SECURITY,
            priority=QueryPriority.HIGH,
            tags=["deploy-code", "security", "hardening", "compliance"],
            min_experts=2,
            max_experts=3,
            expert_timeout=360.0
        )
        
        return result
    
    async def generate_optimized_config(self, consultations: Dict[str, Any], target_env: str) -> str:
        """Generate optimized deploy-code configuration based on expert consultations."""
        print(f"\n📝 Generating optimized {target_env} configuration based on expert advice...")
        
        # Extract key recommendations from consultations
        architecture_insights = self._extract_insights(consultations.get('architecture', {}))
        optimization_insights = self._extract_insights(consultations.get('optimization', {}))
        security_insights = self._extract_insights(consultations.get('security', {}))
        
        # Generate configuration based on insights
        config = self._build_config_from_insights(
            target_env,
            architecture_insights,
            optimization_insights,
            security_insights
        )
        
        # Save the generated configuration
        config_path = f"examples/deploy-code-configs/{target_env}-expert-optimized.yaml"
        
        try:
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
            
            print(f"  ✅ Generated optimized configuration: {config_path}")
            
            # Create a summary of applied recommendations
            summary = self._create_optimization_summary(
                architecture_insights,
                optimization_insights,
                security_insights
            )
            
            summary_path = f"examples/deploy-code-configs/{target_env}-optimization-summary.md"
            with open(summary_path, 'w') as f:
                f.write(summary)
            
            print(f"  📊 Generated optimization summary: {summary_path}")
            
            return config_path
            
        except Exception as e:
            print(f"  ❌ Failed to generate configuration: {e}")
            return None
    
    def _extract_insights(self, consultation_result: Dict[str, Any]) -> List[str]:
        """Extract actionable insights from consultation results."""
        insights = []
        
        responses = consultation_result.get('responses', [])
        for response in responses:
            content = response.get('content', '')
            
            # Simple insight extraction (in practice, this could be more sophisticated)
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                if any(keyword in line.lower() for keyword in [
                    'recommend', 'suggest', 'should', 'use', 'implement',
                    'configure', 'set', 'enable', 'disable'
                ]):
                    insights.append(line)
        
        return insights[:10]  # Limit to top 10 insights
    
    def _build_config_from_insights(self, target_env: str, arch_insights: List[str], 
                                  opt_insights: List[str], sec_insights: List[str]) -> Dict[str, Any]:
        """Build deploy-code configuration from expert insights."""
        
        # Base configuration template
        config = {
            "name": f"{target_env}-expert-optimized",
            "version": "1.0.0",
            "description": f"Expert-optimized configuration for {target_env} environment",
            "generated_by": "circle-of-experts",
            "generated_at": datetime.now().isoformat(),
            "expert_insights": {
                "architecture": arch_insights,
                "optimization": opt_insights,
                "security": sec_insights
            }
        }
        
        # Apply insights based on environment type
        if target_env == "production":
            config.update(self._get_production_config_template())
        elif target_env == "development":
            config.update(self._get_development_config_template())
        else:
            config.update(self._get_minimal_config_template())
        
        # Apply security insights
        if any("network policy" in insight.lower() for insight in sec_insights):
            config.setdefault("security", {})["networkPolicy"] = {"enabled": True}
        
        if any("rbac" in insight.lower() for insight in sec_insights):
            config.setdefault("security", {})["rbac"] = {"enabled": True}
        
        # Apply optimization insights
        if any("horizontal" in insight.lower() for insight in opt_insights):
            config.setdefault("scaling", {})["horizontal"] = {"enabled": True}
        
        if any("monitoring" in insight.lower() for insight in opt_insights):
            config.setdefault("monitoring", {})["enabled"] = True
        
        return config
    
    def _get_production_config_template(self) -> Dict[str, Any]:
        """Get production configuration template."""
        return {
            "target": {"type": "kubernetes", "namespace": "production"},
            "runtime": {
                "replicas": 3,
                "resources": {
                    "requests": {"memory": "512Mi", "cpu": "500m"},
                    "limits": {"memory": "2Gi", "cpu": "2000m"}
                }
            },
            "monitoring": {"enabled": True},
            "security": {"enabled": True},
            "backup": {"enabled": True}
        }
    
    def _get_development_config_template(self) -> Dict[str, Any]:
        """Get development configuration template."""
        return {
            "target": {"type": "docker"},
            "runtime": {
                "command": "npm run dev",
                "environment": {"NODE_ENV": "development"}
            },
            "tools": {"linting": {"enabled": True}},
            "hotReload": {"enabled": True}
        }
    
    def _get_minimal_config_template(self) -> Dict[str, Any]:
        """Get minimal configuration template."""
        return {
            "target": {"type": "local"},
            "runtime": {"command": "npm start"}
        }
    
    def _create_optimization_summary(self, arch_insights: List[str], 
                                   opt_insights: List[str], sec_insights: List[str]) -> str:
        """Create markdown summary of optimization recommendations."""
        summary = f"""# Deploy-code Expert Optimization Summary

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Architecture Recommendations

"""
        
        for i, insight in enumerate(arch_insights, 1):
            summary += f"{i}. {insight}\n"
        
        summary += "\n## Optimization Recommendations\n\n"
        
        for i, insight in enumerate(opt_insights, 1):
            summary += f"{i}. {insight}\n"
        
        summary += "\n## Security Recommendations\n\n"
        
        for i, insight in enumerate(sec_insights, 1):
            summary += f"{i}. {insight}\n"
        
        summary += f"""

## Implementation Notes

This configuration was generated by consulting the Circle of Experts system.
Each recommendation has been validated by multiple AI experts specializing in:

- Infrastructure Architecture
- Performance Optimization  
- Security Hardening
- DevOps Best Practices

Review and adapt these recommendations based on your specific requirements.
"""
        
        return summary


async def demonstrate_deploy_code_expert_consultation():
    """Demonstrate deploy-code optimization using Circle of Experts."""
    print("🎪 Deploy-code + Circle of Experts Integration Demo")
    print("=" * 60)
    print("Generating optimal deployment configurations using AI expert consensus")
    print()
    
    consultation = DeployCodeExpertConsultation()
    
    try:
        # Initialize system
        await consultation.initialize()
        
        # Define project context for consultation
        project_context = {
            "app_type": "Web API",
            "scale": "Medium (1000-10000 users)",
            "tech_stack": ["Python", "FastAPI", "PostgreSQL", "Redis"],
            "environment": "Production",
            "budget": "Moderate",
            "team_size": "5-10 developers",
            "compliance": ["SOC2", "GDPR"]
        }
        
        print(f"📋 Project Context:")
        for key, value in project_context.items():
            if isinstance(value, list):
                value = ", ".join(value)
            print(f"  • {key.replace('_', ' ').title()}: {value}")
        
        # Consult experts for different aspects
        consultations = {}
        
        # Architecture consultation
        consultations['architecture'] = await consultation.consult_deployment_architecture(project_context)
        
        # Configuration optimization consultation
        consultations['optimization'] = await consultation.consult_configuration_optimization("production")
        
        # Security hardening consultation
        consultations['security'] = await consultation.consult_security_hardening(
            "examples/deploy-code-configs/production.yaml"
        )
        
        # Generate optimized configurations for different environments
        environments = ["production", "staging", "development"]
        generated_configs = []
        
        for env in environments:
            config_path = await consultation.generate_optimized_config(consultations, env)
            if config_path:
                generated_configs.append(config_path)
        
        # Display results
        print("\n🎯 Expert Consultation Results:")
        print(f"  • Architecture experts consulted: {len(consultations['architecture'].get('responses', []))}")
        print(f"  • Optimization experts consulted: {len(consultations['optimization'].get('responses', []))}")
        print(f"  • Security experts consulted: {len(consultations['security'].get('responses', []))}")
        print(f"  • Generated configurations: {len(generated_configs)}")
        
        print("\n📁 Generated Files:")
        for config_path in generated_configs:
            if Path(config_path).exists():
                size = Path(config_path).stat().st_size
                print(f"  ✅ {config_path} ({size} bytes)")
        
        print("\n💡 Expert-Driven Benefits:")
        print("  • Multi-expert consensus on architecture decisions")
        print("  • Validated security hardening recommendations") 
        print("  • Performance optimization from domain experts")
        print("  • Best practice configuration patterns")
        print("  • Compliance-aware deployment strategies")
        print("  • Automated configuration generation")
        
        return consultations
        
    except Exception as e:
        print(f"\n💥 Expert consultation error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("🚀 Starting Deploy-code Expert Consultation Demo...")
    print()
    
    try:
        result = asyncio.run(demonstrate_deploy_code_expert_consultation())
        print("\n🎉 Deploy-code Expert Consultation Demo Complete!")
        
    except KeyboardInterrupt:
        print("\n⏹️  Demo interrupted by user")
    except Exception as e:
        print(f"\n💥 Demo failed: {e}")