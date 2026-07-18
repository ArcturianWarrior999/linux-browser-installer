"""
Metadata Validation Module
Ensures structural integrity of LLC account data before deployment
"""

import json
import hashlib
import re
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class ValidationResult:
    is_valid: bool
    errors: List[str]
    warnings: List[str]

class MetadataValidator:
    """Validates LLC account metadata against security and integrity standards."""
    
    REQUIRED_FIELDS = {'llcName', 'currentBalance', 'originalAmount', 'status', 'timeline'}
    FORBIDDEN_KEYWORDS = {'distortion', 'hijack', 'exploit', '<script>', 'eval('}
    STATUS_WHITELIST = {'active', 'delinquent', 'recovered', 'quarantined'}
    
    def __init__(self):
        self.validation_log = []
    
    def validate_payload(self, payload: Dict[str, Any]) -> ValidationResult:
        """
        Validate a single LLC account payload.
        
        Args:
            payload: Dictionary representing an LLC account
            
        Returns:
            ValidationResult with validation status and messages
        """
        errors = []
        warnings = []
        
        # Check required fields
        missing_fields = self.REQUIRED_FIELDS - set(payload.keys())
        if missing_fields:
            errors.append(f"Missing required fields: {missing_fields}")
        
        # Validate LLC name for malicious content
        if 'llcName' in payload:
            llc_name = payload['llcName']
            for keyword in self.FORBIDDEN_KEYWORDS:
                if keyword.lower() in llc_name.lower():
                    errors.append(f"Forbidden keyword detected in llcName: '{keyword}'")
            
            if len(llc_name) > 255:
                errors.append("llcName exceeds maximum length (255 characters)")
        
        # Validate status
        if 'status' in payload:
            if payload['status'] not in self.STATUS_WHITELIST:
                errors.append(f"Invalid status: '{payload['status']}'. Must be one of {self.STATUS_WHITELIST}")
        
        # Validate financial data
        errors.extend(self._validate_financials(payload))
        
        # Validate timeline
        if 'timeline' in payload:
            errors.extend(self._validate_timeline(payload['timeline']))
        
        is_valid = len(errors) == 0
        
        # Log validation
        self.validation_log.append({
            'llcName': payload.get('llcName', 'UNKNOWN'),
            'valid': is_valid,
            'errors': errors,
            'warnings': warnings
        })
        
        return ValidationResult(is_valid=is_valid, errors=errors, warnings=warnings)
    
    def _validate_financials(self, payload: Dict[str, Any]) -> List[str]:
        """Validate financial fields for integrity."""
        errors = []
        
        try:
            current = float(payload.get('currentBalance', 0))
            original = float(payload.get('originalAmount', 0))
            
            if current < 0:
                errors.append("currentBalance cannot be negative")
            if original < 0:
                errors.append("originalAmount cannot be negative")
            if current > original:
                errors.append("currentBalance exceeds originalAmount")
            
            # Check for suspicious precision
            if len(str(current).split('.')[-1]) > 2:
                errors.append("Financial value exceeds 2 decimal places")
                
        except (ValueError, TypeError) as e:
            errors.append(f"Invalid financial data: {str(e)}")
        
        return errors
    
    def _validate_timeline(self, timeline: List[Dict[str, Any]]) -> List[str]:
        """Validate timeline events for duplicates and integrity."""
        errors = []
        seen_ids = set()
        
        if not isinstance(timeline, list):
            errors.append("Timeline must be a list")
            return errors
        
        for idx, event in enumerate(timeline):
            if 'id' not in event:
                errors.append(f"Timeline event {idx} missing 'id' field")
                continue
            
            event_id = event['id']
            
            # Check for duplicates (frequency amplification attack)
            if event_id in seen_ids:
                errors.append(f"Duplicate timeline event ID detected: '{event_id}' (Frequency Amplification)")
            
            seen_ids.add(event_id)
            
            # Validate event structure
            if 'timestamp' not in event:
                errors.append(f"Timeline event {idx} missing 'timestamp'")
        
        return errors
    
    def generate_integrity_hash(self, payload: Dict[str, Any]) -> str:
        """Generate SHA-256 hash of payload for integrity verification."""
        payload_str = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(payload_str.encode()).hexdigest()
    
    def get_validation_report(self) -> Dict[str, Any]:
        """Get summary of all validations performed."""
        valid_count = sum(1 for log in self.validation_log if log['valid'])
        total_count = len(self.validation_log)
        
        return {
            'summary': {
                'total_validations': total_count,
                'passed': valid_count,
                'failed': total_count - valid_count,
                'pass_rate': f"{(valid_count/total_count*100):.1f}%" if total_count > 0 else "N/A"
            },
            'logs': self.validation_log
        }

def validate_json_file(filepath: str) -> ValidationResult:
    """Load and validate a JSON file containing LLC account data."""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        validator = MetadataValidator()
        
        # Handle both single object and array of objects
        if isinstance(data, dict):
            return validator.validate_payload(data)
        elif isinstance(data, list):
            results = [validator.validate_payload(item) for item in data]
            # Aggregate results
            all_errors = []
            all_warnings = []
            for result in results:
                all_errors.extend(result.errors)
                all_warnings.extend(result.warnings)
            return ValidationResult(
                is_valid=all(r.is_valid for r in results),
                errors=all_errors,
                warnings=all_warnings
            )
        else:
            return ValidationResult(is_valid=False, errors=["JSON must be object or array"], warnings=[])
    
    except json.JSONDecodeError as e:
        return ValidationResult(is_valid=False, errors=[f"Invalid JSON: {str(e)}"], warnings=[])
    except FileNotFoundError:
        return ValidationResult(is_valid=False, errors=[f"File not found: {filepath}"], warnings=[])

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        result = validate_json_file(filepath)
        print(json.dumps({
            'valid': result.is_valid,
            'errors': result.errors,
            'warnings': result.warnings
        }, indent=2))
        sys.exit(0 if result.is_valid else 1)
    else:
        print("Usage: python validate_metadata.py <filepath>")
