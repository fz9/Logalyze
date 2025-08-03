import re
import os
import logging
import psutil
from datetime import datetime, timedelta
from collections import Counter, defaultdict


def parse_timestamp_to_iso(timestamp_str):
    """
    Parse timestamp from various ModSecurity log formats to ISO format for proper sorting.
    Returns ISO format string or None if parsing fails.
    """
    if not timestamp_str or timestamp_str == 'N/A':
        return None
    
    try:
        # Handle common ModSecurity timestamp formats
        # Example: "29/Jun/2023:21:44:15 +0000" or "28/Jul/2025:07:01:09.941362 --0700"
        if '/' in timestamp_str and ':' in timestamp_str:
            # Parse format: 29/Jun/2023:21:44:15 +0000 or with microseconds
            date_part = timestamp_str.split(' ')[0]  # Get "29/Jun/2023:21:44:15" or "28/Jul/2025:07:01:09.941362"
            if ':' in date_part:
                date_time = date_part.split(':')
                date = date_time[0]  # "29/Jun/2023"
                time = ':'.join(date_time[1:4])  # "21:44:15" or "07:01:09.941362"
                
                # Handle microseconds by truncating them
                if '.' in time:
                    time = time.split('.')[0]  # "07:01:09"
                
                # Parse the date and time
                if '/' in date and len(date_time) >= 3:
                    try:
                        # Parse format: 29/Jun/2023 21:44:15
                        dt = datetime.strptime(f"{date} {time}", '%d/%b/%Y %H:%M:%S')
                        return dt.isoformat()
                    except ValueError:
                        pass
        
        # Handle ISO format: 2023-06-29T21:44:15
        if 'T' in timestamp_str:
            try:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                return dt.isoformat()
            except ValueError:
                pass
        
        # Fallback: try to parse as datetime
        for fmt in ['%Y-%m-%d %H:%M:%S', '%d/%b/%Y:%H:%M:%S', '%Y-%m-%dT%H:%M:%S']:
            try:
                dt = datetime.strptime(timestamp_str.split(' ')[0], fmt)
                return dt.isoformat()
            except ValueError:
                continue
        
        # If all else fails, return None
        return None
        
    except Exception:
        return None


def format_timestamp_for_display(iso_timestamp):
    """
    Format ISO timestamp to human-readable format for display.
    """
    if not iso_timestamp:
        return 'N/A'
    
    try:
        dt = datetime.fromisoformat(iso_timestamp)
        return dt.strftime('%d %b %H:%M')
    except (ValueError, TypeError):
        return str(iso_timestamp)


def parse_modsec_log(log_path, max_file_size_mb=1024):
    """
    Parses a ModSecurity audit log file and groups sections by transaction ID.
    
    Args:
        log_path: Path to the log file
        max_file_size_mb: Maximum file size in MB (default: 1024MB = 1GB)
    """
    if not os.path.exists(log_path):
        return {"error": "Log file not found."}
    
    # Check file size to prevent memory exhaustion
    try:
        file_size = os.path.getsize(log_path)
        max_size_bytes = max_file_size_mb * 1024 * 1024
        if file_size > max_size_bytes:
            return {"error": f"File size ({file_size / (1024*1024):.1f}MB) exceeds maximum allowed size ({max_file_size_mb}MB)."}
    except OSError as e:
        return {"error": f"Unable to check file size: {str(e)}"}
    
    # Check available memory to prevent exhaustion
    try:
        memory = psutil.virtual_memory()
        available_mb = memory.available / (1024 * 1024)
        file_size_mb = file_size / (1024 * 1024)
        
        # Require at least 3x the file size in available memory for safe processing
        # This accounts for Python object overhead and parsing structures
        required_memory_mb = file_size_mb * 3
        
        if available_mb < required_memory_mb:
            return {"error": f"Insufficient memory. Available: {available_mb:.0f}MB, Required: {required_memory_mb:.0f}MB (3x file size for safe processing)."}
            
        logging.info(f"Memory check passed. Available: {available_mb:.0f}MB, File: {file_size_mb:.1f}MB")
    except ImportError:
        logging.warning("psutil not available, skipping memory check")
    except Exception as e:
        logging.warning(f"Memory check failed: {str(e)}")

    transactions = {}  # Dictionary to group by transaction ID
    current_transaction_id = None
    current_part = None
    current_section_data = None

    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                try:
                    boundary_match = re.match(r'--([0-9a-fA-F]+)-([A-Z])--', line)
                    if boundary_match:
                        transaction_id = boundary_match.group(1)
                        section = boundary_match.group(2)
                        
                        # Initialize transaction if not exists
                        if transaction_id not in transactions:
                            transactions[transaction_id] = {
                                "id": transaction_id,  # Remove dashes
                                "timestamp": None,  # Store ISO format for sorting
                                "display_timestamp": "N/A",  # Store display format
                                "source_ip": "N/A",
                                "source_port": "N/A",
                                "destination_port": "N/A",
                                "request_line": "N/A",
                                "response_status": "N/A",
                                "messages": [],
                                "raw_messages": [],  # Store full raw message content
                                "sections": {}
                            }
                        
                        # Save previous section data
                        if current_section_data and current_transaction_id and current_part:
                            transactions[current_transaction_id]["sections"][current_part] = current_section_data
                        
                        current_transaction_id = transaction_id
                        current_part = section
                        current_section_data = {
                            "section": section,
                            "content": [],
                            "timestamp": None,
                            "display_timestamp": "N/A",
                            "source_ip": "N/A",
                            "source_port": "N/A",
                            "destination_port": "N/A",
                            "request_line": "N/A",
                            "response_status": "N/A",
                            "messages": []
                        }
                        
                        # Handle section A boundary line with basic timestamp extraction
                        if section == 'A':
                            # Extract timestamp from boundary line if present
                            timestamp_match = re.search(r'\[(.*?)\]', line)
                            if timestamp_match:
                                raw_timestamp = timestamp_match.group(1)
                                iso_timestamp = parse_timestamp_to_iso(raw_timestamp)
                                display_timestamp = format_timestamp_for_display(iso_timestamp)
                                transactions[transaction_id]['timestamp'] = iso_timestamp
                                transactions[transaction_id]['display_timestamp'] = display_timestamp
                                current_section_data['timestamp'] = iso_timestamp
                                current_section_data['display_timestamp'] = display_timestamp
                        
                        continue

                    if not current_transaction_id or not current_section_data:
                        continue
                    
                    line = line.strip()
                    if not line:
                        continue

                    # Store raw content for each section
                    current_section_data["content"].append(line)
                    
                    # Extract main transaction data from appropriate sections
                    if current_part == 'A':
                        # In section A, look for network information in content lines
                        # Format: timestamp unique_id source_ip source_port dest_ip dest_port
                        # Or: [timestamp] unique_id source_ip source_port dest_ip dest_port
                        
                        # First try to extract timestamp if not already set
                        timestamp_match = re.search(r'\[(.*?)\]', line)
                        if timestamp_match:
                            raw_timestamp = timestamp_match.group(1)
                            iso_timestamp = parse_timestamp_to_iso(raw_timestamp)
                            display_timestamp = format_timestamp_for_display(iso_timestamp)
                            transactions[current_transaction_id]['timestamp'] = iso_timestamp
                            transactions[current_transaction_id]['display_timestamp'] = display_timestamp
                            current_section_data['timestamp'] = iso_timestamp
                            current_section_data['display_timestamp'] = display_timestamp
                        
                        # Look for network information pattern: IP PORT IP PORT
                        # This handles lines like: "165.154.182.179 40660 10.0.1.57 80"
                        network_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)', line)
                        if network_match:
                            source_ip = network_match.group(1)
                            source_port = network_match.group(2)
                            dest_ip = network_match.group(3)  # We'll use this for dest_port extraction
                            dest_port = network_match.group(4)
                            
                            transactions[current_transaction_id]['source_ip'] = source_ip
                            transactions[current_transaction_id]['source_port'] = source_port
                            transactions[current_transaction_id]['destination_port'] = dest_port
                            
                            current_section_data['source_ip'] = source_ip
                            current_section_data['source_port'] = source_port
                            current_section_data['destination_port'] = dest_port

                    elif current_part == 'B':
                        # Request line is the first line in section B
                        if current_section_data['request_line'] == 'N/A':
                            current_section_data['request_line'] = line
                            # Use first request line as main request line
                            if transactions[current_transaction_id]['request_line'] == 'N/A':
                                transactions[current_transaction_id]['request_line'] = line
                        
                        # Alternative source IP extraction from section B (fallback)
                        if line.lower().startswith('source:'):
                            ip_port = line.split(' ')[1] if len(line.split(' ')) > 1 else 'N/A'
                            if ':' in ip_port:
                                ip, port = ip_port.split(':', 1)
                                if transactions[current_transaction_id]['source_ip'] == 'N/A':
                                    transactions[current_transaction_id]['source_ip'] = ip
                                    current_section_data['source_ip'] = ip
                                if transactions[current_transaction_id]['source_port'] == 'N/A':
                                    transactions[current_transaction_id]['source_port'] = port
                                    current_section_data['source_port'] = port
                            else:
                                if transactions[current_transaction_id]['source_ip'] == 'N/A':
                                    transactions[current_transaction_id]['source_ip'] = ip_port
                                    current_section_data['source_ip'] = ip_port

                    elif current_part == 'F':
                        # Response status is the first line in section F
                        if line.lower().startswith('http/'):
                            current_section_data['response_status'] = line
                            # Use first response status as main status
                            if transactions[current_transaction_id]['response_status'] == 'N/A':
                                transactions[current_transaction_id]['response_status'] = line

                    elif current_part == 'H':
                        # Messages are in section H - store both raw and parsed content
                        if line.lower().startswith('message:') or line.lower().startswith('apache-error:') or line.lower().startswith('apache-handler:') or line.lower().startswith('stopwatch:') or line.lower().startswith('producer:') or line.lower().startswith('server:') or line.lower().startswith('engine-mode:'):
                            # Store the full raw line for modal display
                            transactions[current_transaction_id]['raw_messages'].append(line)
                            
                            # Also extract the parsed message for table display
                            if line.lower().startswith('message:'):                    
                                msg_match = re.search(r'\[msg "(.*?)"\]', line)
                                if msg_match:
                                    message = msg_match.group(1)
                                    current_section_data['messages'].append(message)
                                    transactions[current_transaction_id]['messages'].append(message)
                
                except Exception as e:
                    # Log parsing error for this line but continue processing
                    logging.warning(f"Error parsing line in {log_path}: {str(e)}")
                    continue

    except IOError as e:
        return {"error": f"Error reading file: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error while parsing: {str(e)}"}

    # Save the last section
    if current_section_data and current_transaction_id and current_part:
        transactions[current_transaction_id]["sections"][current_part] = current_section_data

    # Convert to list and add section count
    result = []
    for trans_id, trans_data in transactions.items():
        trans_data['section_count'] = len(trans_data['sections'])
        trans_data['section_list'] = sorted(trans_data['sections'].keys())
        result.append(trans_data)
    
    # Sort by timestamp (newest first) - use ISO timestamp for proper sorting
    result.sort(key=lambda x: x['timestamp'] or '1900-01-01T00:00:00', reverse=True)
    
    return result


def calculate_timestamp_range_modsec(logs):
    """
    Calculate timestamp range from parsed ModSecurity logs.
    Returns display timestamps for UI consistency.
    """
    if not logs:
        return {'min': None, 'max': None}
    
    # Collect display timestamps for UI
    timestamps = [log.get('display_timestamp') for log in logs 
                  if log.get('display_timestamp') and log.get('display_timestamp') != 'N/A']
    
    if not timestamps:
        return {'min': None, 'max': None}
    
    # Sort display timestamps properly for date range
    def parse_display_timestamp(ts_str):
        """Parse display timestamp for proper sorting."""
        try:
            from datetime import datetime
            current_year = datetime.now().year
            # Parse format: "29 Jun 21:44"
            dt = datetime.strptime(f"{ts_str} {current_year}", '%d %b %H:%M %Y')
            return dt
        except ValueError:
            return datetime(1900, 1, 1)
    
    sorted_timestamps = sorted(timestamps, key=parse_display_timestamp)
    
    return {
        'min': sorted_timestamps[0],
        'max': sorted_timestamps[-1]
    }


def get_dashboard_data(logs):
    """
    Generate dashboard data from parsed logs.
    """
    # Count requests by IP
    ip_counts = Counter()
    status_timeline = defaultdict(lambda: defaultdict(int))  # {hour: {status: count}}
    
    # Track timestamp range for slider
    timestamps = []
    
    for log_entry in logs:
        # Count IPs
        if log_entry['source_ip'] != 'N/A':
            ip_counts[log_entry['source_ip']] += 1
        
        # Collect timestamps for range calculation - use display timestamps for UI
        if log_entry.get('display_timestamp') and log_entry['display_timestamp'] != 'N/A':
            timestamps.append(log_entry['display_timestamp'])
        
        # Status codes over time (exclude 200)
        if log_entry['response_status'] != 'N/A' and log_entry.get('timestamp'):
            try:
                # Extract status code number
                status_match = re.search(r'(\d{3})', log_entry['response_status'])
                if status_match:
                    status_code = status_match.group(1)
                    # Exclude 200 status codes
                    if status_code != '200':
                        # Use ISO timestamp for proper time bucketing
                        iso_timestamp = log_entry['timestamp']
                        if iso_timestamp:
                            try:
                                dt = datetime.fromisoformat(iso_timestamp)
                                # Create hour bucket in display format for consistency
                                hour_bucket = dt.strftime('%d %b %H:00')
                                status_timeline[hour_bucket][status_code] += 1
                            except ValueError:
                                pass
            except Exception as e:
                print(f"Error processing status timeline: {e}")
    
    # Get top 10 IPs
    top_ips = dict(ip_counts.most_common(10))
    
    # Convert timeline to chart format with smart date/time labels
    timeline_data = []
    status_codes = set()
    
    # Sort time buckets using proper date parsing
    def parse_hour_bucket(hour_str):
        """Parse hour bucket string to datetime for proper sorting."""
        try:
            # Parse format: "29 Jun 21:00"
            # Add current year for parsing
            from datetime import datetime
            current_year = datetime.now().year
            dt = datetime.strptime(f"{hour_str} {current_year}", '%d %b %H:%M %Y')
            return dt
        except ValueError:
            # Fallback: return a very old date for unparseable strings
            return datetime(1900, 1, 1)
    
    sorted_hours = sorted(status_timeline.keys(), key=parse_hour_bucket)
    
    previous_date = None
    
    for hour in sorted_hours:
        # Extract date and time parts from "29 Jun 21:00" format
        if ' ' in hour and ':' in hour:
            try:
                date_part = hour.rsplit(' ', 1)[0]  # "29 Jun"
                time_part = hour.rsplit(' ', 1)[1]  # "21:00"
                
                # Show date only if it's different from previous
                if date_part != previous_date:
                    display_time = hour  # Show full "29 Jun 21:00"
                    previous_date = date_part
                else:
                    display_time = time_part  # Show only "21:00"
            except (ValueError, IndexError):
                display_time = hour  # Fallback to original
        else:
            display_time = hour  # Fallback to original
        
        hour_data = {'time': display_time}
        for status, count in status_timeline[hour].items():
            hour_data[status] = count
            status_codes.add(status)
        timeline_data.append(hour_data)
    
    # Status codes are already collected in the loop above
    
    # Determine timestamp range using proper date sorting
    timestamp_range = None
    if timestamps:
        # Sort display timestamps properly
        def parse_display_timestamp(ts_str):
            """Parse display timestamp for proper sorting."""
            try:
                from datetime import datetime
                current_year = datetime.now().year
                # Parse format: "29 Jun 21:44"
                dt = datetime.strptime(f"{ts_str} {current_year}", '%d %b %H:%M %Y')
                return dt
            except ValueError:
                return datetime(1900, 1, 1)
        
        sorted_timestamps = sorted(timestamps, key=parse_display_timestamp)
        timestamp_range = {
            "min": sorted_timestamps[0],
            "max": sorted_timestamps[-1]
        }
    
    return {
        "top_ips": top_ips,
        "status_timeline": timeline_data,
        "status_codes": sorted(list(status_codes)),
        "timestamp_range": timestamp_range
    } 