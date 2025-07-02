from flask import Flask, jsonify, render_template, request, redirect, url_for
import re
import os
import logging
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from werkzeug.utils import secure_filename
import glob
import threading
import time
import apache_error_parser
import modsecurity_parser

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MODSECURITY_FOLDER'] = 'uploads/modsec'
app.config['APACHE_ERROR_FOLDER'] = 'uploads/apache/error'
app.config['APACHE_ACCESS_FOLDER'] = 'uploads/apache/access'
app.config['MAX_CONTENT_LENGTH'] = 300 * 1024 * 1024  # 300MB max file size

# Security headers function
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    # Content Security Policy
    csp = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com; "
        "script-src-attr 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'deny';"
    )
    response.headers['Content-Security-Policy'] = csp
    
    # Additional security headers
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response

# Ensure upload directories exist (they should already exist)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['MODSECURITY_FOLDER'], exist_ok=True)
os.makedirs(app.config['APACHE_ERROR_FOLDER'], exist_ok=True)
os.makedirs(app.config['APACHE_ACCESS_FOLDER'], exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'log', 'txt'}

# File cleanup configuration
CLEANUP_OLDER_THAN_DAYS = 30  # Delete files older than 30 days
MAX_STORAGE_SIZE_MB = 5000  # Maximum 5GB total storage
CLEANUP_INTERVAL_HOURS = 24  # Run cleanup every 24 hours

# Storage management and cleanup functionality
def get_directory_size(directory):
    """Calculate total size of directory in bytes."""
    total_size = 0
    try:
        for dirpath, dirnames, filenames in os.walk(directory):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    total_size += os.path.getsize(filepath)
    except Exception as e:
        print(f"Error calculating directory size: {e}")
    return total_size

def cleanup_old_files():
    """Remove files older than specified days and manage storage limits."""
    cleanup_count = 0
    total_cleaned_size = 0
    
    # Get cutoff date
    cutoff_date = datetime.now() - timedelta(days=CLEANUP_OLDER_THAN_DAYS)
    
    # Directories to clean
    directories_to_clean = [
        app.config['APACHE_ERROR_FOLDER'],
        app.config['MODSECURITY_FOLDER']
    ]
    
    for directory in directories_to_clean:
        try:
            for filename in os.listdir(directory):
                filepath = os.path.join(directory, filename)
                
                if os.path.isfile(filepath):
                    # Check file age
                    file_modified_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                    
                    if file_modified_time < cutoff_date:
                        file_size = os.path.getsize(filepath)
                        os.remove(filepath)
                        cleanup_count += 1
                        total_cleaned_size += file_size
                        print(f"Cleaned up old file: {filepath}")
                        
        except Exception as e:
            print(f"Error during cleanup of {directory}: {e}")
    
    # Check storage limits and clean oldest files if needed
    total_storage_size = get_directory_size(app.config['UPLOAD_FOLDER'])
    max_storage_bytes = MAX_STORAGE_SIZE_MB * 1024 * 1024
    
    if total_storage_size > max_storage_bytes:
        print(f"Storage limit exceeded: {total_storage_size / (1024*1024):.1f}MB > {MAX_STORAGE_SIZE_MB}MB")
        cleanup_count += cleanup_by_storage_limit()
    
    if cleanup_count > 0:
        print(f"Cleanup complete: removed {cleanup_count} files, freed {total_cleaned_size / (1024*1024):.1f}MB")
    
    return cleanup_count

def cleanup_by_storage_limit():
    """Remove oldest files when storage limit is exceeded."""
    cleanup_count = 0
    
    # Get all files with modification times
    all_files = []
    directories = [app.config['APACHE_ERROR_FOLDER'], app.config['MODSECURITY_FOLDER']]
    
    for directory in directories:
        try:
            for filename in os.listdir(directory):
                filepath = os.path.join(directory, filename)
                if os.path.isfile(filepath):
                    modified_time = os.path.getmtime(filepath)
                    file_size = os.path.getsize(filepath)
                    all_files.append((filepath, modified_time, file_size))
        except Exception as e:
            print(f"Error listing files in {directory}: {e}")
    
    # Sort by modification time (oldest first)
    all_files.sort(key=lambda x: x[1])
    
    # Remove oldest files until under storage limit
    max_storage_bytes = MAX_STORAGE_SIZE_MB * 1024 * 1024
    current_storage = get_directory_size(app.config['UPLOAD_FOLDER'])
    
    for filepath, _, file_size in all_files:
        if current_storage <= max_storage_bytes:
            break
            
        try:
            os.remove(filepath)
            current_storage -= file_size
            cleanup_count += 1
            print(f"Removed file due to storage limit: {filepath}")
        except Exception as e:
            print(f"Error removing file {filepath}: {e}")
    
    return cleanup_count

def background_cleanup_task():
    """Background task to run file cleanup periodically."""
    while True:
        try:
            time.sleep(CLEANUP_INTERVAL_HOURS * 3600)  # Convert hours to seconds
            print("Running scheduled file cleanup...")
            cleanup_old_files()
        except Exception as e:
            print(f"Error in background cleanup task: {e}")
            time.sleep(3600)  # Wait 1 hour before retrying

# Start background cleanup task
cleanup_thread = threading.Thread(target=background_cleanup_task, daemon=True)
cleanup_thread.start()

# Run initial cleanup on startup
cleanup_old_files()

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_available_files():
    """Get list of available ModSecurity log files (both default and uploaded)."""
    files = []
    
    # Add default file if it exists
    if os.path.exists('modsec_audit.log'):
        files.append({
            'filename': 'modsec_audit.log',
            'display_name': 'modsec_audit.log (default)',
            'is_default': True,
            'modified': os.path.getmtime('modsec_audit.log')
        })
    
    # Add uploaded ModSecurity files from uploads/modsec/
    for file_path in glob.glob(os.path.join(app.config['MODSECURITY_FOLDER'], '*')):
        if os.path.isfile(file_path):
            filename = os.path.basename(file_path)
            if allowed_file(filename):
                files.append({
                    'filename': filename,
                    'display_name': filename,
                    'is_default': False,
                    'modified': os.path.getmtime(file_path),
                    'upload_path': file_path
                })
    
    # Sort by modification time (newest first)
    files.sort(key=lambda x: x['modified'], reverse=True)
    
    return files

def get_available_apache_error_files():
    """Get list of available Apache error log files."""
    files = []
    
    # Add uploaded Apache error files from uploads/apache/error/
    for file_path in glob.glob(os.path.join(app.config['APACHE_ERROR_FOLDER'], '*')):
        if os.path.isfile(file_path):
            filename = os.path.basename(file_path)
            if allowed_file(filename):
                files.append({
                    'filename': filename,
                    'display_name': filename,
                    'is_default': False,
                    'modified': os.path.getmtime(file_path),
                    'upload_path': file_path
                })
    
    # Sort by modification time (newest first)
    files.sort(key=lambda x: x['modified'], reverse=True)
    
    return files

def get_file_path(filename, log_type='modsecurity'):
    """Get the full path for a log file."""
    if filename == 'modsec_audit.log' and os.path.exists('modsec_audit.log'):
        return 'modsec_audit.log'
    
    # Check appropriate folder based on log type
    if log_type == 'apache-error':
        upload_path = os.path.join(app.config['APACHE_ERROR_FOLDER'], secure_filename(filename))
    else:  # Default to modsecurity
        upload_path = os.path.join(app.config['MODSECURITY_FOLDER'], secure_filename(filename))
    
    if os.path.exists(upload_path):
        return upload_path
    
    return None



    """
    Parses a ModSecurity audit log file and groups sections by transaction ID.
    """
    if not os.path.exists(log_path):
        return {"error": "Log file not found."}

    transactions = {}  # Dictionary to group by transaction ID
    current_transaction_id = None
    current_part = None
    current_section_data = None

    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
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
            except (ValueError, IndexError):
                pass
    
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
    
    # Calculate timestamp range for slider
    timestamp_range = {
        'min': None,
        'max': None
    }
    
    if timestamps:
        # Sort timestamps and get range
        sorted_timestamps = sorted(timestamps)
        timestamp_range['min'] = sorted_timestamps[0]
        timestamp_range['max'] = sorted_timestamps[-1]
    
    return {
        'top_ips': top_ips,
        'status_timeline': timeline_data,
        'status_codes': sorted(list(status_codes)),
        'timestamp_range': timestamp_range
    }

@app.route('/api/modsecurity/files')
def get_modsecurity_files():
    """Get list of available ModSecurity log files."""
    files = get_available_files()
    return jsonify({'files': files})

@app.route('/api/modsecurity/upload', methods=['POST'])
def upload_modsecurity_file():
    """Handle ModSecurity file upload."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        
        # Add timestamp to avoid conflicts
        name, ext = os.path.splitext(filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{name}_{timestamp}{ext}"
        
        upload_folder = app.config['MODSECURITY_FOLDER']
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'file_size': file_size,
            'upload_timestamp': timestamp,
            'message': f'ModSecurity log file uploaded successfully as {filename}'
        })
    
    return jsonify({'error': 'Invalid file type. Only .log and .txt files are allowed.'}), 400

@app.route('/api/modsecurity/logs')
def get_modsecurity_logs():
    """Get ModSecurity logs from specified file or default file."""
    filename = request.args.get('file', 'modsec_audit.log')
    file_path = get_file_path(filename)
    
    if not file_path:
        return jsonify({'error': f'File {filename} not found'}), 404
    
    logs = modsecurity_parser.parse_modsec_log(file_path)
    if isinstance(logs, dict) and 'error' in logs:
        return jsonify(logs)
    
    # Add timestamp range for slider
    timestamps = [log['timestamp'] for log in logs if log['timestamp'] != 'N/A']
    timestamp_range = {
        'min': None,
        'max': None
    }
    
    if timestamps:
        sorted_timestamps = sorted(timestamps)
        timestamp_range['min'] = sorted_timestamps[0]
        timestamp_range['max'] = sorted_timestamps[-1]
    
    return jsonify({
        'logs': logs,
        'timestamp_range': timestamp_range
    })

@app.route('/api/modsecurity/dashboard')
def get_modsecurity_dashboard():
    """Get ModSecurity dashboard data from specified file or default file."""
    filename = request.args.get('file', 'modsec_audit.log')
    file_path = get_file_path(filename)
    
    if not file_path:
        return jsonify({'error': f'File {filename} not found'}), 404
    
    logs = modsecurity_parser.parse_modsec_log(file_path)
    if isinstance(logs, dict) and 'error' in logs:
        return jsonify(logs)
    
    dashboard_data = modsecurity_parser.get_dashboard_data(logs)
    return jsonify(dashboard_data)

# Apache Error Log API endpoints
@app.route('/api/apache-error/files')
def get_apache_error_files():
    """Get list of available Apache error log files."""
    files = get_available_apache_error_files()
    return jsonify({
        'files': files,
        'total': len(files)
    })

@app.route('/api/apache-error/upload', methods=['POST'])
def upload_apache_error_file():
    """Handle Apache error log file upload."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        
        # Add timestamp to avoid conflicts
        name, ext = os.path.splitext(filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{name}_{timestamp}{ext}"
        
        file_path = os.path.join(app.config['APACHE_ERROR_FOLDER'], filename)
        file.save(file_path)
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'file_size': file_size,
            'upload_timestamp': timestamp,
            'message': f'Apache error log file uploaded successfully as {filename}'
        })
    
    return jsonify({'error': 'Invalid file type. Only .log and .txt files are allowed.'}), 400

@app.route('/api/apache-error/files/<filename>', methods=['DELETE'])
def delete_apache_error_file(filename):
    """Delete specific Apache error log file."""
    try:
        file_path = get_file_path(filename, 'apache-error')
        if not file_path:
            return jsonify({'error': f'File {filename} not found'}), 404
        
        os.remove(file_path)
        return jsonify({
            'success': True,
            'message': f'File {filename} deleted successfully'
        })
    except Exception as e:
        logging.error(f'Error deleting file {filename}: {str(e)}')
        return jsonify({'error': 'An internal server error occurred while deleting the file.'}), 500

@app.route('/api/apache-error/logs')
def get_apache_error_logs():
    """Get Apache error logs from specified file with pagination."""
    filename = request.args.get('file')
    if not filename:
        return jsonify({'error': 'File parameter is required'}), 400
    
    # Pagination parameters
    page = int(request.args.get('page', 1))
    limit = min(int(request.args.get('limit', 100)), 1000)  # Max 1000 per page
    
    file_path = get_file_path(filename, 'apache-error')
    
    if not file_path:
        return jsonify({'error': f'File {filename} not found'}), 404
    
    try:
        # The parser returns (entries, stats) tuple
        logs, stats = apache_error_parser.parse_apache_error_log(file_path)
        
        if logs:
            total_count = len(logs)
            
            # Apply pagination
            start_idx = (page - 1) * limit
            end_idx = start_idx + limit
            paginated_logs = logs[start_idx:end_idx]
            
            # Calculate timestamp range for time filtering
            timestamps = [log.get('timestamp') for log in logs if log.get('timestamp') and log.get('timestamp') != 'N/A']
            timestamp_range = {
                'min': None,
                'max': None
            }
            
            if timestamps:
                sorted_timestamps = sorted(timestamps)
                timestamp_range['min'] = sorted_timestamps[0]
                timestamp_range['max'] = sorted_timestamps[-1]
            
            return jsonify({
                'logs': paginated_logs,
                'total_count': total_count,
                'page': page,
                'limit': limit,
                'total_pages': (total_count + limit - 1) // limit,
                'timestamp_range': timestamp_range,
                'stats': stats
            })
        else:
            return jsonify({'error': 'No logs found in file'}), 404
            
    except Exception as e:
        logging.error(f'Error parsing Apache error log {filename}: {str(e)}')
        return jsonify({'error': 'An internal server error occurred while parsing the log file.'}), 500

@app.route('/api/apache-error/dashboard')
def get_apache_error_dashboard():
    """Get dashboard data for Apache error logs."""
    filename = request.args.get('file')
    if not filename:
        return jsonify({'error': 'File parameter is required'}), 400
    
    file_path = get_file_path(filename, 'apache-error')
    
    if not file_path:
        return jsonify({'error': f'File {filename} not found'}), 404
    
    try:
        # The parser returns (entries, stats) tuple
        logs, stats = apache_error_parser.parse_apache_error_log(file_path)
        
        if logs:
            dashboard_data = apache_error_parser.get_dashboard_stats(logs)
            
            # Add file stats
            dashboard_data['file_stats'] = stats
            dashboard_data['filename'] = filename
            
            return jsonify(dashboard_data)
        else:
            return jsonify({'error': 'No logs found in file'}), 404
            
    except Exception as e:
        logging.error(f'Error generating dashboard data for {filename}: {str(e)}')
        return jsonify({'error': 'An internal server error occurred while generating dashboard data.'}), 500

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/modsecurity')
def modsecurity():
    return render_template('modsecurity.html')

@app.route('/apache-error')
def apache_error():
    return render_template('apache-error.html')

@app.route('/api/apache-error/test-parse')
def test_apache_error_parse():
    """Test endpoint to verify Apache error parsing works."""
    try:
        # Test with sample file
        sample_file = os.path.join(app.config['APACHE_ERROR_FOLDER'], 'sample_error.log')
        
        if not os.path.exists(sample_file):
            return jsonify({'error': 'Sample file not found', 'path': sample_file})
        
        # Parse the sample file
        logs, stats = apache_error_parser.parse_apache_error_log(sample_file)
        
        return jsonify({
            'success': True,
            'sample_file': sample_file,
            'parsed_entries': len(logs),
            'sample_logs': logs[:3] if logs else [],  # Return first 3 entries
            'stats': stats,
            'message': f'Successfully parsed {len(logs)} entries from sample file'
        })
        
    except Exception as e:
        logging.error(f'Test parse failed: {str(e)}')
        return jsonify({'error': 'An internal server error occurred during test parsing.'}), 500

if __name__ == '__main__':
    app.run(debug=False, port=5001) 