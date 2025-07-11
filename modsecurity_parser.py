import re
import os
import logging
from datetime import datetime, timedelta
from collections import Counter, defaultdict


def format_timestamp(timestamp_str):
    """
    Convert ModSecurity timestamp to human readable format.
    Input: "29/Jun/2025:21:44:25.848984 +0530"
    Output: "29 Jun 21:44"
    """
    if timestamp_str == "N/A":
        return "N/A"
    
    try:
        # Parse the timestamp - format like "29/Jun/2025:21:44:25.848984 +0530"
        # Remove timezone and microseconds for easier parsing
        clean_timestamp = timestamp_str.split(' ')[0]  # Remove timezone
        if '.' in clean_timestamp:
            clean_timestamp = clean_timestamp.split('.')[0]  # Remove microseconds
        
        # Parse the datetime
        dt = datetime.strptime(clean_timestamp, "%d/%b/%Y:%H:%M:%S")
        
        # Format to "29 Jun 21:44"
        return dt.strftime("%d %b %H:%M")
    except (ValueError, IndexError):
        # If parsing fails, return original
        return timestamp_str


def parse_modsec_log(log_path, max_file_size_mb=300, max_line_length=8192, max_lines=50000):
    """
    Parses a ModSecurity audit log file and groups sections by transaction ID.
    
    Args:
        log_path: Path to the log file
        max_file_size_mb: Maximum file size in MB (default: 300MB)
        max_line_length: Maximum line length in characters (default: 8192)
        max_lines: Maximum number of lines to process (default: 50,000)
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

    transactions = {}  # Dictionary to group by transaction ID
    current_transaction_id = None
    current_part = None
    current_section_data = None
    lines_processed = 0

    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                lines_processed += 1
                
                # Limit total lines processed to prevent DoS
                if lines_processed > max_lines:
                    logging.warning(f"Maximum line limit ({max_lines}) reached while parsing {log_path}")
                    break
                
                # Check line length to prevent memory exhaustion
                if len(line) > max_line_length:
                    logging.warning(f"Line {lines_processed} exceeds maximum length ({max_line_length} chars), truncating")
                    line = line[:max_line_length] + '...[TRUNCATED]'
                
                try:
                    boundary_match = re.match(r'--([0-9a-fA-F]+)-([A-Z])--', line)
                    if boundary_match:
                        transaction_id = boundary_match.group(1)
                        section = boundary_match.group(2)
                        
                        # Initialize transaction if not exists
                        if transaction_id not in transactions:
                            transactions[transaction_id] = {
                                "id": transaction_id,  # Remove dashes
                                "timestamp": "N/A",
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
                            "timestamp": "N/A",
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
                                formatted_timestamp = format_timestamp(raw_timestamp)
                                transactions[transaction_id]['timestamp'] = formatted_timestamp
                                current_section_data['timestamp'] = formatted_timestamp
                        
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
                            formatted_timestamp = format_timestamp(raw_timestamp)
                            transactions[current_transaction_id]['timestamp'] = formatted_timestamp
                            current_section_data['timestamp'] = formatted_timestamp
                        
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
                    logging.warning(f"Error parsing line {lines_processed} in {log_path}: {str(e)}")
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
    
    # Sort by timestamp (newest first)
    result.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return result


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
        
        # Collect timestamps for range calculation
        if log_entry['timestamp'] != 'N/A':
            timestamps.append(log_entry['timestamp'])
        
        # Status codes over time (exclude 200)
        if log_entry['response_status'] != 'N/A' and log_entry['timestamp'] != 'N/A':
            try:
                # Extract status code number
                status_match = re.search(r'(\d{3})', log_entry['response_status'])
                if status_match:
                    status_code = status_match.group(1)
                    # Exclude 200 status codes
                    if status_code != '200':
                        # Use timestamp hour as time bucket
                        timestamp_str = log_entry['timestamp']
                        # Format: "29 Jun 21:44" -> use "29 Jun 21:00" as hour bucket
                        if ':' in timestamp_str:
                            hour_bucket = timestamp_str.rsplit(':', 1)[0] + ':00'
                            status_timeline[hour_bucket][status_code] += 1
            except Exception as e:
                print(f"Error processing status timeline: {e}")
    
    # Get top 10 IPs
    top_ips = dict(ip_counts.most_common(10))
    
    # Convert timeline to chart format with smart date/time labels
    timeline_data = []
    status_codes = set()
    
    # Sort time buckets
    sorted_hours = sorted(status_timeline.keys())
    
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
    
    # Determine timestamp range
    timestamp_range = None
    if timestamps:
        timestamp_range = {
            "min": min(timestamps),
            "max": max(timestamps)
        }
    
    return {
        "top_ips": top_ips,
        "status_timeline": timeline_data,
        "status_codes": sorted(list(status_codes)),
        "timestamp_range": timestamp_range
    } 