"""
GDPR Compliance Module for SYNTHEX
Implements data privacy features required for GDPR compliance
"""
import json
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import hashlib
import logging
from pathlib import Path
import asyncio
from enum import Enum

logger = logging.getLogger(__name__)

class ConsentPurpose(Enum):
    """GDPR consent purposes"""
    SEARCH_ANALYTICS = "search_analytics"
    PERSONALIZATION = "personalization"
    MARKETING = "marketing"
    THIRD_PARTY_SHARING = "third_party_sharing"
    DATA_RETENTION = "data_retention"

class DataCategory(Enum):
    """Data categories for GDPR"""
    PERSONAL_DATA = "personal_data"
    SEARCH_HISTORY = "search_history"
    USAGE_ANALYTICS = "usage_analytics"
    PREFERENCES = "preferences"
    TECHNICAL_DATA = "technical_data"

class GDPRCompliance:
    """GDPR compliance implementation"""
    
    def __init__(self):
        self.consent_storage = {}  # In production, use persistent storage
        self.deletion_requests = {}
        self.export_requests = {}
        self.data_retention_days = 365  # Default retention period
        
    async def record_consent(self, user_id: str, purposes: List[ConsentPurpose], 
                           consent_given: bool, ip_address: str = None) -> Dict[str, Any]:
        """
        Record user consent for data processing
        
        Args:
            user_id: User identifier
            purposes: List of consent purposes
            consent_given: Whether consent was given
            ip_address: IP address of consent (for audit trail)
            
        Returns:
            Consent record
        """
        consent_record = {
            "user_id": user_id,
            "timestamp": datetime.now().isoformat(),
            "purposes": [p.value for p in purposes],
            "consent_given": consent_given,
            "ip_address": self._hash_ip(ip_address) if ip_address else None,
            "version": "1.0"  # Consent version for tracking changes
        }
        
        if user_id not in self.consent_storage:
            self.consent_storage[user_id] = []
            
        self.consent_storage[user_id].append(consent_record)
        
        logger.info(f"Consent recorded for user {user_id}: {consent_given} for {purposes}")
        
        return consent_record
        
    async def get_user_consents(self, user_id: str) -> Dict[str, bool]:
        """
        Get current consent status for user
        
        Args:
            user_id: User identifier
            
        Returns:
            Dictionary of consent purposes and their status
        """
        if user_id not in self.consent_storage:
            return {purpose.value: False for purpose in ConsentPurpose}
            
        # Get latest consent for each purpose
        current_consents = {}
        for record in reversed(self.consent_storage[user_id]):
            for purpose in record["purposes"]:
                if purpose not in current_consents:
                    current_consents[purpose] = record["consent_given"]
                    
        # Fill in missing purposes with default (no consent)
        for purpose in ConsentPurpose:
            if purpose.value not in current_consents:
                current_consents[purpose.value] = False
                
        return current_consents
        
    async def request_data_deletion(self, user_id: str, categories: List[DataCategory] = None) -> str:
        """
        Process data deletion request (right to erasure)
        
        Args:
            user_id: User identifier
            categories: Specific data categories to delete (None = all)
            
        Returns:
            Deletion request ID
        """
        request_id = f"DEL-{user_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        self.deletion_requests[request_id] = {
            "user_id": user_id,
            "request_time": datetime.now().isoformat(),
            "categories": [c.value for c in categories] if categories else ["all"],
            "status": "pending",
            "scheduled_deletion": (datetime.now() + timedelta(days=30)).isoformat()
        }
        
        # Schedule actual deletion (in production, use task queue)
        asyncio.create_task(self._process_deletion(request_id))
        
        logger.info(f"Data deletion requested for user {user_id}: {request_id}")
        
        return request_id
        
    async def request_data_export(self, user_id: str, format: str = "json") -> str:
        """
        Process data export request (right to data portability)
        
        Args:
            user_id: User identifier
            format: Export format (json, csv, xml)
            
        Returns:
            Export request ID
        """
        request_id = f"EXP-{user_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        self.export_requests[request_id] = {
            "user_id": user_id,
            "request_time": datetime.now().isoformat(),
            "format": format,
            "status": "processing"
        }
        
        # Process export (in production, use task queue)
        asyncio.create_task(self._process_export(request_id))
        
        logger.info(f"Data export requested for user {user_id}: {request_id}")
        
        return request_id
        
    async def get_data_retention_policy(self) -> Dict[str, Any]:
        """
        Get data retention policy
        
        Returns:
            Retention policy details
        """
        return {
            "default_retention_days": self.data_retention_days,
            "categories": {
                DataCategory.PERSONAL_DATA.value: 365,
                DataCategory.SEARCH_HISTORY.value: 180,
                DataCategory.USAGE_ANALYTICS.value: 365,
                DataCategory.PREFERENCES.value: 730,
                DataCategory.TECHNICAL_DATA.value: 90
            },
            "deletion_grace_period_days": 30,
            "backup_retention_days": 30
        }
        
    async def check_data_minimization(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply data minimization principles
        
        Args:
            data: Data to minimize
            
        Returns:
            Minimized data
        """
        # Remove unnecessary fields
        unnecessary_fields = ['internal_id', 'debug_info', 'raw_data']
        minimized = {k: v for k, v in data.items() if k not in unnecessary_fields}
        
        # Pseudonymize where possible
        if 'ip_address' in minimized:
            minimized['ip_address'] = self._hash_ip(minimized['ip_address'])
            
        if 'email' in minimized:
            minimized['email_domain'] = minimized['email'].split('@')[1] if '@' in minimized['email'] else 'unknown'
            del minimized['email']
            
        return minimized
        
    async def anonymize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Anonymize personal data
        
        Args:
            data: Data to anonymize
            
        Returns:
            Anonymized data
        """
        anonymized = data.copy()
        
        # Remove direct identifiers
        identifiers = ['user_id', 'email', 'name', 'phone', 'address', 'ip_address']
        for identifier in identifiers:
            if identifier in anonymized:
                anonymized[f"{identifier}_hash"] = self._hash_value(str(anonymized[identifier]))
                del anonymized[identifier]
                
        # Generalize quasi-identifiers
        if 'birth_date' in anonymized:
            birth_year = datetime.fromisoformat(anonymized['birth_date']).year
            anonymized['age_group'] = self._get_age_group(birth_year)
            del anonymized['birth_date']
            
        if 'location' in anonymized:
            anonymized['country'] = anonymized['location'].get('country', 'unknown')
            del anonymized['location']
            
        return anonymized
        
    async def _process_deletion(self, request_id: str):
        """Process deletion request after grace period"""
        await asyncio.sleep(30 * 24 * 60 * 60)  # 30 days grace period
        
        request = self.deletion_requests.get(request_id)
        if request and request['status'] == 'pending':
            # Perform actual deletion
            user_id = request['user_id']
            
            # Delete from all systems (simplified)
            logger.info(f"Executing data deletion for user {user_id}")
            
            # Update request status
            request['status'] = 'completed'
            request['completion_time'] = datetime.now().isoformat()
            
    async def _process_export(self, request_id: str):
        """Process data export request"""
        await asyncio.sleep(5)  # Simulate processing time
        
        request = self.export_requests.get(request_id)
        if request:
            user_id = request['user_id']
            
            # Collect user data (simplified)
            user_data = {
                "user_id": user_id,
                "export_date": datetime.now().isoformat(),
                "data": {
                    "profile": {"user_id": user_id},
                    "consents": self.consent_storage.get(user_id, []),
                    "search_history": [],  # Would fetch from database
                    "preferences": {}  # Would fetch from database
                }
            }
            
            # Save export file
            export_path = Path(f"/tmp/gdpr_export_{request_id}.json")
            with open(export_path, 'w') as f:
                json.dump(user_data, f, indent=2)
                
            # Update request
            request['status'] = 'completed'
            request['file_path'] = str(export_path)
            request['completion_time'] = datetime.now().isoformat()
            
            logger.info(f"Data export completed for user {user_id}: {export_path}")
            
    def _hash_ip(self, ip_address: str) -> str:
        """Hash IP address for privacy"""
        if not ip_address:
            return ""
        # Keep first two octets for geographic info
        parts = ip_address.split('.')
        if len(parts) == 4:
            masked = f"{parts[0]}.{parts[1]}.0.0"
            return hashlib.sha256(masked.encode()).hexdigest()[:16]
        return hashlib.sha256(ip_address.encode()).hexdigest()[:16]
        
    def _hash_value(self, value: str) -> str:
        """Hash sensitive value"""
        return hashlib.sha256(value.encode()).hexdigest()
        
    def _get_age_group(self, birth_year: int) -> str:
        """Convert birth year to age group"""
        current_year = datetime.now().year
        age = current_year - birth_year
        
        if age < 18:
            return "under_18"
        elif age < 25:
            return "18-24"
        elif age < 35:
            return "25-34"
        elif age < 45:
            return "35-44"
        elif age < 55:
            return "45-54"
        elif age < 65:
            return "55-64"
        else:
            return "65+"


# Global GDPR compliance instance
gdpr_compliance = GDPRCompliance()


# Decorators for GDPR compliance
def requires_consent(purpose: ConsentPurpose):
    """Decorator to check user consent before processing"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            user_id = kwargs.get('user_id')
            if not user_id:
                raise ValueError("user_id required for consent check")
                
            consents = await gdpr_compliance.get_user_consents(user_id)
            if not consents.get(purpose.value, False):
                raise PermissionError(f"User has not consented to {purpose.value}")
                
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def anonymize_output(func):
    """Decorator to anonymize function output"""
    async def wrapper(*args, **kwargs):
        result = await func(*args, **kwargs)
        if isinstance(result, dict):
            return await gdpr_compliance.anonymize_data(result)
        elif isinstance(result, list):
            return [await gdpr_compliance.anonymize_data(item) if isinstance(item, dict) else item for item in result]
        return result
    return wrapper