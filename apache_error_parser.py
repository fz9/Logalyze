import re
import json
import os
import psutil
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union
import logging

class ApacheErrorLogParser:
    """
    Apache Error Log Parser for parsing standard Apache error log formats.
    
    Supports parsing of Apache error logs with the following format:
    [timestamp] [module:level] [pid processid] [client clientip] message
    """
    
    def __init__(self):
        """Initialize the Apache Error Log Parser with regex patterns."""
        # Main regex pattern for standard Apache error log format
        self.main_pattern = re.compile(
            r'\[(?P<timestamp>[^\]]+)\]\s+'  # [timestamp]
            r'\[(?P<module>[^:]*):(?P<severity>[^\]]*)\]\s+'  # [module:severity]
            r'(?:\[pid\s+(?P<pid>\d+)(?::tid\s+(?P<tid>\d+))?\]\s*)?'  # [pid nnnn:tid nnnn] (optional)
            r'(?:\[client\s+(?P<client_ip>[^\]:]+)(?::(?P<client_port>\d+))?\]\s*)?'  # [client ip:port] (optional)
            r'(?:(?P<error_code>AH\d+):\s*)?'  # Error code (optional)
            r'(?P<message>.*)'  # Message
        )
        
        # Alternative patterns for different Apache log formats
        self.alt_patterns = [
            # Simplified format: [timestamp] [level] message
            re.compile(
                r'\[(?P<timestamp>[^\]]+)\]\s+'
                r'\[(?P<severity>[^\]]+)\]\s+'
                r'(?P<message>.*)'
            ),
            # Format with file/line info: [timestamp] [module:level] [pid] [client] message, referer: url file: /path/file.php line: 123
            re.compile(
                r'\[(?P<timestamp>[^\]]+)\]\s+'
                r'\[(?P<module>[^:]*):(?P<severity>[^\]]*)\]\s+'
                r'(?:\[pid\s+(?P<pid>\d+)\]\s*)?'
                r'(?:\[client\s+(?P<client_ip>[^\]:]+)(?::(?P<client_port>\d+))?\]\s*)?'
                r'(?P<message>.*?)'
                r'(?:,\s*referer:\s+(?P<referer>\S+))?'
                r'(?:\s+file:\s+(?P<file_reference>[^\s]+))?'
                r'(?:\s+line:\s+(?P<line_reference>\d+))?'
            )
        ]
        
        # Severity level mappings for normalization
        self.severity_mapping = {
            'emerg': 'emergency',
            'emergency': 'emergency',
            'alert': 'alert',
            'crit': 'critical',
            'critical': 'critical',
            'err': 'error',
            'error': 'error',
            'warn': 'warning',
            'warning': 'warning',
            'notice': 'notice',
            'info': 'info',
            'debug': 'debug'
        }
        
        # Common Apache modules for validation
        self.known_modules = {
            'core', 'ssl', 'rewrite', 'php', 'fcgid', 'proxy', 'auth_basic',
            'auth_digest', 'authn_file', 'authz_user', 'dir', 'mime', 'negotiation',
            'setenvif', 'status', 'autoindex', 'cgid', 'deflate', 'headers',
            'expires', 'filter', 'include', 'log_config', 'logio', 'mime_magic',
            'unique_id', 'userdir', 'version', 'vhost_alias', 'dav', 'dav_fs',
            'alias', 'speling', 'usertrack', 'cern_meta', 'env', 'asis'
        }
        
        self.stats = {
            'total_lines': 0,
            'parsed_lines': 0,
            'failed_lines': 0,
            'severity_counts': {},
            'module_counts': {}
        }
    
    def normalize_severity(self, severity: str) -> str:
        """Normalize severity level to standard format."""
        if not severity:
            return 'info'
        
        severity_lower = severity.lower().strip()
        return self.severity_mapping.get(severity_lower, severity_lower)
    
    def normalize_module(self, module: str) -> str:
        """Normalize module name to standard format."""
        if not module:
            return 'core'
        
        module_clean = module.lower().strip()
        # Remove common prefixes
        if module_clean.startswith('mod_'):
            module_clean = module_clean[4:]
        
        return module_clean
    
    def parse_timestamp(self, timestamp_str: str) -> Optional[str]:
        """
        Parse timestamp string to ISO format with robust multi-format support.
        Enhanced version with manual parsing and multiple fallbacks.
        """
        if not timestamp_str or timestamp_str.strip() == '':
            return None
        
        timestamp_str = timestamp_str.strip()
        
        try:
            # Handle common Apache timestamp formats with manual parsing first
            # This is more reliable than strptime for malformed timestamps
            
            # Handle format: "Tue Oct 10 14:32:52.123456 2023" or "Tue Oct 10 14:32:52 2023"
            if len(timestamp_str.split()) >= 5 and timestamp_str[0:3].isalpha():
                try:
                    # Try to parse Apache's default format manually
                    parts = timestamp_str.split()
                    if len(parts) >= 5:
                        # Extract time part and handle microseconds
                        time_part = parts[3]
                        if '.' in time_part:
                            time_part = time_part.split('.')[0]  # Remove microseconds
                        
                        # Reconstruct without day name for easier parsing
                        clean_timestamp = f"{parts[1]} {parts[2]} {parts[4]} {time_part}"
                        # Try parsing: "Oct 10 2023 14:32:52"
                        dt = datetime.strptime(clean_timestamp, '%b %d %Y %H:%M:%S')
                        return dt.isoformat()
                except (ValueError, IndexError):
                    pass
            
            # Handle format: "10/Oct/2023:14:32:52 +0000" (Apache access log style)
            if '/' in timestamp_str and ':' in timestamp_str:
                try:
                    # Parse format: 10/Oct/2023:14:32:52 +0000
                    date_part = timestamp_str.split(' ')[0]  # Get "10/Oct/2023:14:32:52"
                    if ':' in date_part and '/' in date_part:
                        # Split date and time
                        date_time_parts = date_part.split(':')
                        if len(date_time_parts) >= 3:
                            date = date_time_parts[0]  # "10/Oct/2023"
                            time = ':'.join(date_time_parts[1:4])  # "14:32:52"
                            
                            # Parse date part
                            if '/' in date:
                                date_parts = date.split('/')
                                if len(date_parts) == 3:
                                    # Reconstruct as standard format
                                    clean_timestamp = f"{date_parts[0]}/{date_parts[1]}/{date_parts[2]} {time}"
                                    dt = datetime.strptime(clean_timestamp, '%d/%b/%Y %H:%M:%S')
                                    return dt.isoformat()
                except (ValueError, IndexError):
                    pass
            
            # Handle ISO format: "2023-10-10T14:32:52" or "2023-10-10T14:32:52Z"
            if 'T' in timestamp_str:
                try:
                    clean_timestamp = timestamp_str.replace('Z', '+00:00')
                    dt = datetime.fromisoformat(clean_timestamp)
                    return dt.isoformat()
                except ValueError:
                    pass
            
            # Fallback: Extended list of Apache timestamp formats
            formats = [
                '%a %b %d %H:%M:%S.%f %Y',  # Tue Oct 10 14:32:52.123456 2023
                '%a %b %d %H:%M:%S %Y',     # Tue Oct 10 14:32:52 2023
                '%Y-%m-%d %H:%M:%S',        # 2023-10-10 14:32:52
                '%Y-%m-%d %H:%M:%S.%f',     # 2023-10-10 14:32:52.123456
                '%d/%b/%Y:%H:%M:%S %z',     # 10/Oct/2023:14:32:52 +0000
                '%d/%b/%Y:%H:%M:%S',        # 10/Oct/2023:14:32:52
                '%d/%b/%Y %H:%M:%S',        # 10/Oct/2023 14:32:52
                '%b %d %H:%M:%S',           # Oct 10 14:32:52 (syslog style)
                '%Y %b %d %H:%M:%S',        # 2023 Oct 10 14:32:52
                '%m/%d/%Y %H:%M:%S',        # 10/10/2023 14:32:52
                '%Y-%m-%dT%H:%M:%S',        # 2023-10-10T14:32:52
                '%Y-%m-%dT%H:%M:%SZ',       # 2023-10-10T14:32:52Z
                '%Y-%m-%dT%H:%M:%S.%f',     # 2023-10-10T14:32:52.123456
                '%Y-%m-%dT%H:%M:%S.%fZ',    # 2023-10-10T14:32:52.123456Z
            ]
            
            # Try each format with timezone stripping
            for fmt in formats:
                try:
                    # Remove timezone info for parsing (but preserve in some formats)
                    test_timestamp = timestamp_str
                    if ' +' in test_timestamp or ' -' in test_timestamp:
                        if '%z' not in fmt:
                            test_timestamp = test_timestamp.split(' +')[0].split(' -')[0]
                    
                    dt = datetime.strptime(test_timestamp, fmt)
                    return dt.isoformat()
                except ValueError:
                    continue
            
            # Last resort: try to extract recognizable patterns
            # Look for YYYY-MM-DD pattern
            date_match = re.search(r'(\d{4}-\d{2}-\d{2})', timestamp_str)
            time_match = re.search(r'(\d{1,2}:\d{2}:\d{2})', timestamp_str)
            
            if date_match and time_match:
                try:
                    combined = f"{date_match.group(1)} {time_match.group(1)}"
                    dt = datetime.strptime(combined, '%Y-%m-%d %H:%M:%S')
                    return dt.isoformat()
                except ValueError:
                    pass
            
            # If all parsing fails, return None for proper sorting
            return None
            
        except Exception:
            # Catch any unexpected errors and return None
            return None
    
    def extract_file_line_info(self, message: str) -> Tuple[str, Optional[str], Optional[int]]:
        """Extract file and line information from message if present."""
        file_reference = None
        line_reference = None
        clean_message = message
        
        # Look for file: /path/to/file pattern
        file_match = re.search(r'file:\s+([^\s,]+)', message)
        if file_match:
            file_reference = file_match.group(1)
            clean_message = re.sub(r',?\s*file:\s+[^\s,]+', '', clean_message)
        
        # Look for line: 123 pattern
        line_match = re.search(r'line:\s+(\d+)', message)
        if line_match:
            line_reference = int(line_match.group(1))
            clean_message = re.sub(r',?\s*line:\s+\d+', '', clean_message)
        
        return clean_message.strip(), file_reference, line_reference
    
    def parse_line(self, line: str) -> Optional[Dict[str, Union[str, int, None]]]:
        """
        Parse a single Apache error log line.
        
        Args:
            line (str): Raw log line
            
        Returns:
            Optional[Dict]: Parsed log entry or None if parsing fails
        """
        if not line or not line.strip():
            return None
        
        line = line.strip()
        self.stats['total_lines'] += 1
        
        # Try main pattern first
        match = self.main_pattern.match(line)
        if not match:
            # Try alternative patterns
            for pattern in self.alt_patterns:
                match = pattern.match(line)
                if match:
                    break
        
        if not match:
            self.stats['failed_lines'] += 1
            # Return a basic structure for unparseable lines
            return {
                'timestamp': None,
                'severity': 'info',
                'module': 'unknown',
                'pid': None,
                'tid': None,
                'client_ip': None,
                'client_port': None,
                'error_code': None,
                'message': line,
                'file_reference': None,
                'line_reference': None,
                'raw_line': line,
                'parse_confidence': 0.1
            }
        
        groups = match.groupdict()
        
        # Parse and normalize data
        timestamp = self.parse_timestamp(groups.get('timestamp', ''))
        severity = self.normalize_severity(groups.get('severity', ''))
        module = self.normalize_module(groups.get('module', ''))
        
        # Extract additional info from message
        message = groups.get('message', '').strip()
        file_reference = groups.get('file_reference')
        line_reference = groups.get('line_reference')
        
        # If file/line info not in groups, try to extract from message
        if not file_reference and not line_reference:
            message, file_reference, line_reference = self.extract_file_line_info(message)
        elif line_reference:
            line_reference = int(line_reference)
        
        # Convert client port to int if present
        client_port = None
        if groups.get('client_port'):
            try:
                client_port = int(groups.get('client_port'))
            except ValueError:
                pass
        
        # Convert PID and TID to int if present
        pid = None
        tid = None
        if groups.get('pid'):
            try:
                pid = int(groups.get('pid'))
            except ValueError:
                pass
        if groups.get('tid'):
            try:
                tid = int(groups.get('tid'))
            except ValueError:
                pass
        
        # Calculate parse confidence
        confidence = 0.5  # Base confidence
        if timestamp: confidence += 0.2
        if severity in self.severity_mapping.values(): confidence += 0.1
        if module in self.known_modules: confidence += 0.1
        if groups.get('pid'): confidence += 0.05
        if groups.get('client_ip'): confidence += 0.05
        
        parsed_entry = {
            'timestamp': timestamp,
            'severity': severity,
            'module': module,
            'pid': pid,
            'tid': tid,
            'client_ip': groups.get('client_ip'),
            'client_port': client_port,
            'error_code': groups.get('error_code'),
            'message': message,
            'file_reference': file_reference,
            'line_reference': line_reference,
            'raw_line': line,
            'parse_confidence': round(confidence, 2)
        }
        
        # Update statistics
        self.stats['parsed_lines'] += 1
        self.stats['severity_counts'][severity] = self.stats['severity_counts'].get(severity, 0) + 1
        self.stats['module_counts'][module] = self.stats['module_counts'].get(module, 0) + 1
        
        return parsed_entry
    
    def parse_file(self, file_path: str, max_file_size_mb: int = 1024) -> List[Dict[str, Union[str, int, None]]]:
        """
        Parse an Apache error log file with enhanced security validation.
        
        Args:
            file_path (str): Path to the log file
            max_file_size_mb (int): Maximum file size in MB (default: 1024MB = 1GB)
            
        Returns:
            List[Dict]: List of parsed log entries
        """
        if not os.path.exists(file_path):
            logging.error(f"Log file not found: {file_path}")
            return []
        
        # Check file size to prevent memory exhaustion
        try:
            file_size = os.path.getsize(file_path)
            max_size_bytes = max_file_size_mb * 1024 * 1024
            if file_size > max_size_bytes:
                logging.error(f"File size ({file_size / (1024*1024):.1f}MB) exceeds maximum allowed size ({max_file_size_mb}MB)")
                return []
        except OSError as e:
            logging.error(f"Unable to check file size for {file_path}: {str(e)}")
            return []
        
        # Check available memory to prevent exhaustion
        try:
            memory = psutil.virtual_memory()
            available_mb = memory.available / (1024 * 1024)
            file_size_mb = file_size / (1024 * 1024)
            
            # Require at least 3x the file size in available memory for safe processing
            # This accounts for Python object overhead and parsing structures
            required_memory_mb = file_size_mb * 3
            
            if available_mb < required_memory_mb:
                logging.error(f"Insufficient memory. Available: {available_mb:.0f}MB, Required: {required_memory_mb:.0f}MB (3x file size for safe processing).")
                return []
                
            logging.info(f"Memory check passed. Available: {available_mb:.0f}MB, File: {file_size_mb:.1f}MB")
        except ImportError:
            logging.warning("psutil not available, skipping memory check")
        except Exception as e:
            logging.warning(f"Memory check failed: {str(e)}")
        
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        parsed_entry = self.parse_line(line)
                        if parsed_entry:
                            entries.append(parsed_entry)
                    except Exception as e:
                        # Log parsing error for this line but continue processing
                        logging.warning(f"Error parsing line {line_num} in {file_path}: {str(e)}")
                        self.stats['failed_lines'] += 1
                        continue
                        
        except IOError as e:
            logging.error(f"Error reading file {file_path}: {str(e)}")
            return []
        except Exception as e:
            logging.error(f"Unexpected error while parsing {file_path}: {str(e)}")
            return []
        
        # Sort entries by timestamp (newest first) for consistent ordering
        entries.sort(key=lambda x: x.get('timestamp') or '1900-01-01T00:00:00', reverse=True)
        return entries
    
    def parse_content(self, content: str, max_lines: Optional[int] = None) -> List[Dict[str, Union[str, int, None]]]:
        """
        Parse Apache error log content from a string.
        
        Args:
            content (str): Raw log content
            max_lines (Optional[int]): Maximum number of lines to parse
            
        Returns:
            List[Dict]: List of parsed log entries
        """
        parsed_entries = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if max_lines and line_num > max_lines:
                break
            
            parsed_entry = self.parse_line(line)
            if parsed_entry:
                parsed_entries.append(parsed_entry)
        
        # Sort entries by timestamp (newest first) for consistent ordering
        parsed_entries.sort(key=lambda x: x.get('timestamp') or '1900-01-01T00:00:00', reverse=True)
        return parsed_entries
    
    def get_stats(self) -> Dict[str, Union[int, float, Dict[str, int]]]:
        """Get parsing statistics."""
        success_rate = 0.0
        if self.stats['total_lines'] > 0:
            success_rate = (self.stats['parsed_lines'] / self.stats['total_lines']) * 100
        
        return {
            'total_lines': self.stats['total_lines'],
            'parsed_lines': self.stats['parsed_lines'],
            'failed_lines': self.stats['failed_lines'],
            'success_rate': round(success_rate, 2),
            'severity_counts': self.stats['severity_counts'],
            'module_counts': self.stats['module_counts']
        }
    
    def reset_stats(self):
        """Reset parsing statistics."""
        self.stats = {
            'total_lines': 0,
            'parsed_lines': 0,
            'failed_lines': 0,
            'severity_counts': {},
            'module_counts': {}
        }
    
    def detect_format(self, sample_lines: List[str]) -> Dict[str, Union[str, float]]:
        """
        Detect the Apache error log format from sample lines.
        
        Args:
            sample_lines (List[str]): Sample log lines for format detection
            
        Returns:
            Dict: Format detection results with confidence score
        """
        if not sample_lines:
            return {'format': 'unknown', 'confidence': 0.0}
        
        # Test each line against patterns
        main_pattern_matches = 0
        alt_pattern_matches = 0
        total_valid_lines = 0
        
        for line in sample_lines[:min(50, len(sample_lines))]:  # Test up to 50 lines
            if not line.strip():
                continue
            
            total_valid_lines += 1
            
            if self.main_pattern.match(line.strip()):
                main_pattern_matches += 1
            else:
                for pattern in self.alt_patterns:
                    if pattern.match(line.strip()):
                        alt_pattern_matches += 1
                        break
        
        if total_valid_lines == 0:
            return {'format': 'unknown', 'confidence': 0.0}
        
        main_confidence = main_pattern_matches / total_valid_lines
        alt_confidence = alt_pattern_matches / total_valid_lines
        
        if main_confidence > 0.8:
            return {'format': 'standard_apache_error', 'confidence': main_confidence}
        elif alt_confidence > 0.6:
            return {'format': 'alternative_apache_error', 'confidence': alt_confidence}
        elif (main_confidence + alt_confidence) > 0.5:
            return {'format': 'mixed_apache_error', 'confidence': main_confidence + alt_confidence}
        else:
            return {'format': 'unknown', 'confidence': main_confidence + alt_confidence}


def parse_apache_error_log(file_path: str) -> Tuple[List[Dict], Dict]:
    """
    Convenience function to parse Apache error log file.
    
    Args:
        file_path (str): Path to the log file
        
    Returns:
        Tuple[List[Dict], Dict]: Parsed entries and statistics
    """
    parser = ApacheErrorLogParser()
    entries = parser.parse_file(file_path)
    stats = parser.get_stats()
    
    # Add timestamp range calculation for consistency with ModSecurity parser
    timestamp_range = calculate_timestamp_range(entries)
    stats['timestamp_range'] = timestamp_range
    
    return entries, stats


def calculate_timestamp_range(logs: List[Dict]) -> Dict:
    """
    Calculate timestamp range from parsed log entries.
    
    Args:
        logs (List[Dict]): List of parsed log entries
        
    Returns:
        Dict: Timestamp range with min and max values
    """
    if not logs:
        return {'min': None, 'max': None}
    
    # Collect valid timestamps
    timestamps = [log.get('timestamp') for log in logs 
                  if log.get('timestamp') and log.get('timestamp') is not None]
    
    if not timestamps:
        return {'min': None, 'max': None}
    
    # Sort timestamps (ISO format sorts correctly)
    sorted_timestamps = sorted(timestamps)
    
    return {
        'min': sorted_timestamps[0],
        'max': sorted_timestamps[-1]
    }


def parse_apache_error_content(content: str, max_lines: Optional[int] = None) -> Tuple[List[Dict], Dict]:
    """
    Convenience function to parse Apache error log content.
    
    Args:
        content (str): Raw log content
        max_lines (Optional[int]): Maximum number of lines to parse
        
    Returns:
        Tuple[List[Dict], Dict]: Parsed entries and statistics
    """
    parser = ApacheErrorLogParser()
    entries = parser.parse_content(content, max_lines)
    stats = parser.get_stats()
    return entries, stats


def get_dashboard_stats(logs: List[Dict]) -> Dict:
    """
    Generate dashboard statistics from parsed Apache error log entries.
    
    Args:
        logs (List[Dict]): List of parsed log entries
        
    Returns:
        Dict: Dashboard statistics including severity distribution, timeline data, 
              top modules, and frequent error messages
    """
    if not logs:
        return {
            'severity_distribution': [],
            'timeline_data': [],
            'top_modules': [],
            'frequent_messages': []
        }
    
    severity_counts = {}
    module_counts = {}
    message_counts = {}
    timeline_data = {}
    
    for log_entry in logs:
        # Count severity levels
        severity = log_entry.get('severity', 'unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count modules
        module = log_entry.get('module', 'unknown')
        module_counts[module] = module_counts.get(module, 0) + 1
        
        # Count error messages (first 100 chars for grouping)
        message = log_entry.get('message', '')
        if message:
            short_message = message[:100] + ('...' if len(message) > 100 else '')
            message_counts[short_message] = message_counts.get(short_message, 0) + 1
        
        # Timeline data - group by hour
        timestamp = log_entry.get('timestamp')
        if timestamp and timestamp != 'N/A':
            try:
                # Parse ISO format timestamp and group by hour
                if isinstance(timestamp, str):
                    if 'T' in timestamp:  # ISO format
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    else:
                        # Try to parse other formats
                        dt = datetime.strptime(timestamp.split('.')[0], '%Y-%m-%d %H:%M:%S')
                    
                    hour_key = dt.strftime('%Y-%m-%d %H:00')
                    timeline_data[hour_key] = timeline_data.get(hour_key, 0) + 1
            except (ValueError, AttributeError):
                # Skip unparseable timestamps
                pass
    
    # Convert to lists for frontend
    severity_distribution = [
        {'severity': severity, 'count': count}
        for severity, count in sorted(severity_counts.items(), key=lambda x: x[1], reverse=True)
    ]
    
    # Get top 10 modules
    top_modules = [
        {'module': module, 'count': count}
        for module, count in sorted(module_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ]
    
    # Get top 10 frequent messages
    frequent_messages = [
        {'message': message, 'count': count}
        for message, count in sorted(message_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ]
    
    # Convert timeline data to sorted list
    timeline_list = [
        {'time': time, 'count': count}
        for time, count in sorted(timeline_data.items())
    ]
    
    return {
        'severity_distribution': severity_distribution,
        'timeline_data': timeline_list,
        'top_modules': top_modules,
        'frequent_messages': frequent_messages,
        'total_entries': len(logs),
        'unique_modules': len(module_counts),
        'unique_severities': len(severity_counts)
    }


if __name__ == "__main__":
    # Example usage and testing
    sample_logs = [
        "[Tue Oct 10 14:32:52.123456 2023] [ssl:error] [pid 12345] [client 192.168.1.100:54321] AH02032: Hostname example.com provided via SNI, but no matching vhost found",
        "[Wed Oct 11 09:15:30 2023] [rewrite:notice] [pid 98765] [client 10.0.0.1:45678] AH00670: Options FollowSymLinks and SymLinksIfOwnerMatch are both off, so the RewriteRule directive is also disabled",
        "[Thu Oct 12 16:45:22 2023] [php:error] [pid 11111] [client 203.0.113.5:33333] PHP Fatal error: Uncaught Error: Call to undefined function mysql_connect() in /var/www/html/config.php:15",
        "[Fri Oct 13 12:30:15 2023] [core:error] [pid 22222] [client 198.51.100.10:22222] AH00124: Request exceeded the limit of 10 internal redirects due to probable configuration error",
        "[Sat Oct 14 08:20:05 2023] [auth_basic:error] [pid 33333] [client 172.16.0.50:11111] AH01617: user admin: authentication failure for \"/admin\": Password Mismatch"
    ]
    
    parser = ApacheErrorLogParser()
    
    print("Testing Apache Error Log Parser")
    print("=" * 50)
    
    for i, log_line in enumerate(sample_logs, 1):
        print(f"\nTest {i}: Parsing log line")
        print(f"Input: {log_line}")
        
        result = parser.parse_line(log_line)
        if result:
            print(f"✓ Parsed successfully (confidence: {result['parse_confidence']})")
            print(f"  Timestamp: {result['timestamp']}")
            print(f"  Severity: {result['severity']}")
            print(f"  Module: {result['module']}")
            print(f"  Client IP: {result['client_ip']}")
            print(f"  Message: {result['message']}")
        else:
            print("✗ Failed to parse")
    
    print(f"\nParsing Statistics:")
    stats = parser.get_stats()
    print(f"Success rate: {stats['success_rate']}%")
    print(f"Severity distribution: {stats['severity_counts']}")
    print(f"Module distribution: {stats['module_counts']}")
    
    # Test format detection
    print(f"\nFormat Detection:")
    format_info = parser.detect_format(sample_logs)
    print(f"Detected format: {format_info['format']} (confidence: {format_info['confidence']:.2f})") 