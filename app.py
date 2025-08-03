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
CLEANUP_INTERVAL_HOURS = 168  # Run cleanup every 7 days

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
    
    # Calculate timestamp range using parser function
    timestamp_range = modsecurity_parser.calculate_timestamp_range_modsec(logs)
    
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
            
            # Use timestamp range from parser (calculated during parsing)
            timestamp_range = stats.get('timestamp_range', {'min': None, 'max': None})
            
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