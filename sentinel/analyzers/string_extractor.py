"""
Advanced String Extraction - Extract IOCs, patterns, obfuscated strings
"""

import re
import base64
import string
from typing import Dict, Any, List, Set
import logging

logger = logging.getLogger(__name__)


class AdvancedStringExtractor:
    """Extract and analyze strings from binaries"""
    
    # Regex patterns for IOCs
    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    URL_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    DOMAIN_PATTERN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.IGNORECASE)
    BITCOIN_PATTERN = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
    ETHEREUM_PATTERN = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
    FILE_PATH_PATTERN = re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*')
    REGISTRY_PATTERN = re.compile(r'HKEY_[A-Z_]+\\[^\s]+', re.IGNORECASE)
    MUTEX_PATTERN = re.compile(r'Global\\[A-Za-z0-9_-]+')
    
    # Suspicious keywords
    SUSPICIOUS_KEYWORDS = [
        # Ransomware
        'encrypt', 'decrypt', 'ransom', 'bitcoin', 'payment', 'key_data',
        # RAT/Trojan
        'keylog', 'screenshot', 'webcam', 'backdoor', 'remote', 'shell',
        # C2
        'command', 'control', 'beacon', 'callback', 'exfiltrate',
        # Credentials
        'password', 'credential', 'token', 'api_key', 'secret',
        # Evasion
        'sandbox', 'vm', 'debug', 'analysis', 'av', 'antivirus',
    ]
    
    def extract(self, file_path: str, min_length: int = 4) -> Dict[str, Any]:
        """
        Extract all strings and IOCs from file
        
        Args:
            file_path: Path to file
            min_length: Minimum string length
            
        Returns:
            Extracted strings and IOCs
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Extract ASCII and Unicode strings
            ascii_strings = self._extract_ascii_strings(data, min_length)
            unicode_strings = self._extract_unicode_strings(data, min_length)
            
            all_strings = list(set(ascii_strings + unicode_strings))
            
            # Extract IOCs
            iocs = self._extract_iocs(all_strings)
            
            # Find suspicious keywords
            suspicious = self._find_suspicious_keywords(all_strings)
            
            # Decode obfuscated strings
            decoded = self._decode_obfuscated_strings(all_strings)
            
            # Extract high-entropy strings (possible encryption)
            high_entropy = self._find_high_entropy_strings(all_strings)
            
            return {
                'total_strings': len(all_strings),
                'ascii_count': len(ascii_strings),
                'unicode_count': len(unicode_strings),
                'iocs': iocs,
                'suspicious_keywords': suspicious,
                'decoded_strings': decoded,
                'high_entropy_strings': high_entropy,
                'sample_strings': all_strings[:100]  # First 100 for display
            }
            
        except Exception as e:
            logger.error(f"String extraction failed: {e}")
            return {'error': str(e)}
    
    def _extract_ascii_strings(self, data: bytes, min_length: int) -> List[str]:
        """Extract ASCII strings"""
        ascii_chars = set(string.printable.encode('ascii'))
        result = []
        current_string = b''
        
        for byte in data:
            if bytes([byte]) in ascii_chars:
                current_string += bytes([byte])
            else:
                if len(current_string) >= min_length:
                    try:
                        result.append(current_string.decode('ascii'))
                    except:
                        pass
                current_string = b''
        
        if len(current_string) >= min_length:
            try:
                result.append(current_string.decode('ascii'))
            except:
                pass
        
        return result
    
    def _extract_unicode_strings(self, data: bytes, min_length: int) -> List[str]:
        """Extract Unicode (UTF-16) strings"""
        result = []
        current_string = b''
        
        for i in range(0, len(data) - 1, 2):
            # UTF-16 LE: ASCII char followed by null byte
            if data[i+1] == 0 and 32 <= data[i] <= 126:
                current_string += bytes([data[i]])
            else:
                if len(current_string) >= min_length:
                    try:
                        result.append(current_string.decode('ascii'))
                    except:
                        pass
                current_string = b''
        
        if len(current_string) >= min_length:
            try:
                result.append(current_string.decode('ascii'))
            except:
                pass
        
        return result
    
    def _extract_iocs(self, strings: List[str]) -> Dict[str, List[str]]:
        """Extract IOCs from strings"""
        iocs = {
            'ip_addresses': [],
            'urls': [],
            'domains': [],
            'emails': [],
            'file_paths': [],
            'registry_keys': [],
            'mutexes': [],
            'crypto_addresses': []
        }
        
        for s in strings:
            # IPs
            ips = self.IP_PATTERN.findall(s)
            iocs['ip_addresses'].extend(ips)
            
            # URLs
            urls = self.URL_PATTERN.findall(s)
            iocs['urls'].extend(urls)
            
            # Emails
            emails = self.EMAIL_PATTERN.findall(s)
            iocs['emails'].extend(emails)
            
            # Domains (exclude IPs)
            domains = self.DOMAIN_PATTERN.findall(s)
            for domain in domains:
                if not self.IP_PATTERN.match(domain):
                    iocs['domains'].append(domain)
            
            # File paths
            paths = self.FILE_PATH_PATTERN.findall(s)
            iocs['file_paths'].extend(paths)
            
            # Registry keys
            reg_keys = self.REGISTRY_PATTERN.findall(s)
            iocs['registry_keys'].extend(reg_keys)
            
            # Mutexes
            mutexes = self.MUTEX_PATTERN.findall(s)
            iocs['mutexes'].extend(mutexes)
            
            # Crypto addresses
            btc = self.BITCOIN_PATTERN.findall(s)
            eth = self.ETHEREUM_PATTERN.findall(s)
            iocs['crypto_addresses'].extend(btc + eth)
        
        # Remove duplicates and limit
        for key in iocs:
            iocs[key] = list(set(iocs[key]))[:50]  # Max 50 per category
        
        return iocs
    
    def _find_suspicious_keywords(self, strings: List[str]) -> List[Dict[str, str]]:
        """Find suspicious keywords in strings"""
        findings = []
        
        for s in strings:
            s_lower = s.lower()
            for keyword in self.SUSPICIOUS_KEYWORDS:
                if keyword in s_lower:
                    findings.append({
                        'keyword': keyword,
                        'context': s[:100]  # First 100 chars
                    })
        
        return findings[:50]  # Max 50
    
    def _decode_obfuscated_strings(self, strings: List[str]) -> List[Dict[str, str]]:
        """Try to decode obfuscated strings"""
        decoded = []
        
        for s in strings:
            # Try Base64
            if len(s) > 20 and len(s) % 4 == 0:
                try:
                    # Check if it looks like base64
                    if re.match(r'^[A-Za-z0-9+/]+={0,2}$', s):
                        decoded_bytes = base64.b64decode(s)
                        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                        
                        # Check if decoded string is meaningful
                        if decoded_str.isprintable() and len(decoded_str) > 4:
                            decoded.append({
                                'encoding': 'base64',
                                'original': s[:50],
                                'decoded': decoded_str[:100]
                            })
                except:
                    pass
            
            # Try Hex
            if len(s) > 10 and len(s) % 2 == 0:
                try:
                    if re.match(r'^[0-9a-fA-F]+$', s):
                        decoded_bytes = bytes.fromhex(s)
                        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                        
                        if decoded_str.isprintable() and len(decoded_str) > 4:
                            decoded.append({
                                'encoding': 'hex',
                                'original': s[:50],
                                'decoded': decoded_str[:100]
                            })
                except:
                    pass
        
        return decoded[:20]  # Max 20
    
    def _find_high_entropy_strings(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Find high-entropy strings (possible encryption/encoding)"""
        high_entropy = []
        
        for s in strings:
            if len(s) < 20:
                continue
            
            # Calculate entropy
            entropy = 0
            length = len(s)
            freq = {}
            
            for char in s:
                freq[char] = freq.get(char, 0) + 1
            
            for count in freq.values():
                p = count / length
                entropy -= p * (p and (p * 0.301029995664))  # log2 approximation
            
            # Flag high entropy strings
            if entropy > 0.9:  # Normalized entropy > 0.9
                high_entropy.append({
                    'string': s[:50],
                    'length': len(s),
                    'entropy': round(entropy, 2)
                })
        
        return high_entropy[:20]  # Max 20
