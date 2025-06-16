"""
Reactive Scaling - Metric-based reactive scaling strategy
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Any


class ReactiveScaling:
    """Reactive scaling strategy implementation"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def react_to_metrics(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """React to current metrics"""
        await asyncio.sleep(0.1)
        
        cpu_util = metrics.get('cpu_utilization', 50)
        if cpu_util > 80:
            action = 'scale_up'
        elif cpu_util < 20:
            action = 'scale_down'
        else:
            action = 'maintain'
            
        return {
            'action': action,
            'confidence': 0.9,
            'reason': f'CPU utilization is {cpu_util}%',
            'simulated': True
        }