import os
import psutil
import winreg
import hashlib
import json
from pathlib import Path
import time
import re

class DoomsdayDetector:
    def __init__(self):
        # Specific processes for better detection
        self.suspicious_processes = [
            'doomsday.exe',
            'doomsdayclient.exe'
        ]
        
        # Client-specific files
        self.suspicious_files = [
            'doomsday.jar',
            'doomsdayclient.jar',
            'doomsday-client.jar'
        ]
        
        # Specific directories (more restrictive)
        self.suspicious_dirs = [
            'doomsday',
            'doomsdayclient',
            'doomsday-client'
        ]
        
        # Known hashes of malicious files (add as needed)
        self.known_malicious_hashes = {
            # Add MD5/SHA256 hashes of known Doomsday versions
            # 'hash_md5': 'doomsday_version_x.x'
        }
        
        self.minecraft_dirs = [
            os.path.expanduser('~/.minecraft'),
            os.path.expanduser('~/AppData/Roaming/.minecraft'),
            os.path.expanduser('~/AppData/Local/.minecraft')
        ]
        
        # Paths that commonly cause false positives
        self.whitelist_paths = [
            'doom eternal',
            'doomsday engine',  # Legitimate game engine
            'doomsday book',
            'doomsday clock',
            'doomsday preppers',
            'program files',
            'program files (x86)',
            'windows',
            'system32'
        ]
        
        self.results = {
            'processes': [],
            'files': [],
            'registry': [],
            'network': [],
            'java_args': [],
            'suspicious_mods': []
        }
    
    def is_whitelisted_path(self, path):
        """Check if a path is whitelisted to avoid false positives"""
        path_lower = path.lower()
        return any(whitelist in path_lower for whitelist in self.whitelist_paths)
    
    def calculate_file_hash(self, file_path):
        """Calculate MD5 hash of a file"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return None
    
    def check_running_processes(self):
        """Check running processes with better accuracy"""
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
            try:
                proc_name = proc.info['name'].lower()
                cmdline = proc.info['cmdline'] or []
                exe_path = proc.info.get('exe', '')
                
                # Stricter verification for specific processes
                for suspicious in self.suspicious_processes:
                    if proc_name == suspicious.lower():
                        # Verify it's not a false positive
                        if not self.is_whitelisted_path(exe_path):
                            self.results['processes'].append({
                                'pid': proc.info['pid'],
                                'name': proc.info['name'],
                                'cmdline': cmdline,
                                'exe_path': exe_path
                            })
                
                # Improved verification for Java processes
                if proc_name in ['java.exe', 'javaw.exe'] and cmdline:
                    cmdline_str = ' '.join(cmdline).lower()
                    
                    # Look for specific Doomsday patterns
                    doomsday_patterns = [
                        r'doomsday(?:client)?\.jar',
                        r'-jar.*doomsday',
                        r'doomsday.*main',
                        r'doomsday.*client'
                    ]
                    
                    for pattern in doomsday_patterns:
                        if re.search(pattern, cmdline_str):
                            # Verify it's not a legitimate game
                            if not any(game in cmdline_str for game in ['doom eternal', 'doom 2016', 'doomsday engine']):
                                self.results['java_args'].append({
                                    'pid': proc.info['pid'],
                                    'cmdline': cmdline,
                                    'pattern_matched': pattern
                                })
                                break
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def check_filesystem(self):
        """Search for suspicious files with better accuracy"""
        search_paths = [
            os.path.expanduser('~/Downloads'),
            os.path.expanduser('~/Desktop'),
            os.path.expanduser('~/Documents'),
            'C:\\Users\\Public\\Downloads',
            'C:\\Temp',
            'C:\\Windows\\Temp'
        ]
        
        for search_path in search_paths:
            if os.path.exists(search_path):
                self._search_directory(search_path)
    
    def _search_directory(self, directory):
        """Search directories with better filtering"""
        try:
            for root, dirs, files in os.walk(directory):
                # Skip system directories and other common ones
                if self.is_whitelisted_path(root):
                    continue
                    
                # Check suspicious directories
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    if self._is_suspicious_directory(dir_name, dir_path):
                        self.results['files'].append({
                            'path': dir_path,
                            'type': 'directory',
                            'confidence': 'high'
                        })
                
                # Check suspicious files
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    if self._is_suspicious_file(file_name, file_path):
                        file_info = {
                            'path': file_path,
                            'type': 'file',
                            'size': os.path.getsize(file_path),
                            'confidence': 'medium'
                        }
                        
                        # Check hash if it's a JAR file
                        if file_name.endswith('.jar'):
                            file_hash = self.calculate_file_hash(file_path)
                            if file_hash and file_hash in self.known_malicious_hashes:
                                file_info['hash'] = file_hash
                                file_info['confidence'] = 'high'
                                file_info['known_version'] = self.known_malicious_hashes[file_hash]
                        
                        self.results['files'].append(file_info)
                    
                    # Check JAR files for suspicious content
                    if file_name.endswith('.jar') and not self.is_whitelisted_path(file_path):
                        self._check_jar_file(file_path)
                        
        except PermissionError:
            pass
    
    def _is_suspicious_directory(self, dir_name, dir_path):
        """Check if a directory is suspicious"""
        dir_name_lower = dir_name.lower()
        
        # Check exact names first
        if dir_name_lower in self.suspicious_dirs:
            return not self.is_whitelisted_path(dir_path)
        
        # Check more specific patterns
        suspicious_patterns = [
            r'^doomsday$',
            r'^doomsdayclient$',
            r'^doomsday-client$',
            r'^doomsday[_-]?v?\d+\.?\d*$'  # doomsday_v1.2, doomsday-2.0, etc.
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, dir_name_lower):
                return not self.is_whitelisted_path(dir_path)
        
        return False
    
    def _is_suspicious_file(self, file_name, file_path):
        """Check if a file is suspicious"""
        file_name_lower = file_name.lower()
        
        # Check exact names
        if file_name_lower in self.suspicious_files:
            return not self.is_whitelisted_path(file_path)
        
        # Check specific patterns for JAR files
        if file_name.endswith('.jar'):
            suspicious_jar_patterns = [
                r'^doomsday.*\.jar$',
                r'^doomsdayclient.*\.jar$',
                r'^doomsday-client.*\.jar$'
            ]
            
            for pattern in suspicious_jar_patterns:
                if re.match(pattern, file_name_lower):
                    return not self.is_whitelisted_path(file_path)
        
        return False
    
    def _check_jar_file(self, jar_path):
        """Analyze JAR file contents"""
        try:
            import zipfile
            with zipfile.ZipFile(jar_path, 'r') as jar:
                file_list = jar.namelist()
                
                # Look for specific patterns inside the JAR
                suspicious_patterns = [
                    r'.*doomsday.*\.class$',
                    r'.*doomsdayclient.*\.class$',
                    r'doomsday/.*',
                    r'net/doomsday/.*'
                ]
                
                for file in file_list:
                    for pattern in suspicious_patterns:
                        if re.match(pattern, file.lower()):
                            self.results['suspicious_mods'].append({
                                'jar_path': jar_path,
                                'suspicious_file': file,
                                'pattern': pattern,
                                'confidence': 'high'
                            })
                            return  # Only need one match
                            
        except Exception:
            pass
    
    def check_minecraft_directory(self):
        """Check Minecraft directories"""
        for mc_dir in self.minecraft_dirs:
            if os.path.exists(mc_dir):
                # Check mods
                mods_dir = os.path.join(mc_dir, 'mods')
                if os.path.exists(mods_dir):
                    self._search_directory(mods_dir)
                
                # Check custom versions
                versions_dir = os.path.join(mc_dir, 'versions')
                if os.path.exists(versions_dir):
                    self._check_versions_directory(versions_dir)
                
                # Check logs with better accuracy
                logs_dir = os.path.join(mc_dir, 'logs')
                if os.path.exists(logs_dir):
                    self._check_logs_directory(logs_dir)
    
    def _check_versions_directory(self, versions_dir):
        """Check Minecraft custom versions"""
        try:
            for version_folder in os.listdir(versions_dir):
                version_path = os.path.join(versions_dir, version_folder)
                if os.path.isdir(version_path):
                    if self._is_suspicious_directory(version_folder, version_path):
                        self.results['files'].append({
                            'path': version_path,
                            'type': 'minecraft_version',
                            'confidence': 'high'
                        })
        except Exception:
            pass
    
    def _check_logs_directory(self, logs_dir):
        """Check Minecraft logs with better accuracy"""
        try:
            for log_file in os.listdir(logs_dir):
                if log_file.endswith('.log'):
                    log_path = os.path.join(logs_dir, log_file)
                    try:
                        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # Look for specific patterns instead of just "doomsday"
                            suspicious_log_patterns = [
                                r'doomsday.*client',
                                r'doomsdayclient',
                                r'loading.*doomsday',
                                r'doomsday.*mod.*loaded'
                            ]
                            
                            for pattern in suspicious_log_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    self.results['files'].append({
                                        'path': log_path,
                                        'type': 'log_file',
                                        'reason': f'Contains pattern: {pattern}',
                                        'confidence': 'medium'
                                    })
                                    break
                    except Exception:
                        pass
        except Exception:
            pass
    
    def check_registry(self):
        """Check Windows registry"""
        try:
            registry_paths = [
                (winreg.HKEY_CURRENT_USER, r"Software"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
            ]
            
            for root_key, subkey in registry_paths:
                self._search_registry(root_key, subkey)
                
        except ImportError:
            pass
        except Exception:
            pass
    
    def _search_registry(self, root_key, subkey):
        """Search for suspicious registry entries"""
        try:
            with winreg.OpenKey(root_key, subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        
                        # Check specific patterns
                        if self._is_suspicious_registry_entry(name, str(value)):
                            self.results['registry'].append({
                                'key': subkey,
                                'name': name,
                                'value': value,
                                'confidence': 'high'
                            })
                        i += 1
                    except WindowsError:
                        break
        except Exception:
            pass
    
    def _is_suspicious_registry_entry(self, name, value):
        """Check if a registry entry is suspicious"""
        combined = f"{name} {value}".lower()
        
        # Specific patterns for registry
        suspicious_patterns = [
            r'doomsday.*client',
            r'doomsdayclient',
            r'doomsday.*\.jar',
            r'doomsday.*\.exe'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, combined):
                # Check it's not a false positive
                if not any(fp in combined for fp in ['doom eternal', 'doomsday engine', 'doomsday book']):
                    return True
        
        return False
    
    def generate_report(self):
        """Generate detailed report with confidence levels"""
        # Calculate detections by confidence level
        high_confidence = 0
        medium_confidence = 0
        
        for category in ['processes', 'files', 'registry', 'java_args', 'suspicious_mods']:
            for item in self.results[category]:
                confidence = item.get('confidence', 'medium')
                if confidence == 'high':
                    high_confidence += 1
                else:
                    medium_confidence += 1
        
        total_detections = high_confidence + medium_confidence
        
        # Create report
        report_content = "DOOMSDAY CLIENT DETECTION REPORT\n"
        report_content += "=" * 40 + "\n\n"
        
        if total_detections == 0:
            print("No traces of Doomsday Client detected")
            report_content += "RESULT: CLEAN - No Doomsday Client detected\n"
        else:
            confidence_level = "HIGH" if high_confidence > 0 else "MEDIUM"
            print(f"DETECTED {total_detections} SUSPICIOUS ITEMS (Confidence: {confidence_level})")
            
            report_content += f"DETECTED {total_detections} SUSPICIOUS ITEMS\n"
            report_content += f"- High confidence: {high_confidence}\n"
            report_content += f"- Medium confidence: {medium_confidence}\n\n"
            
            # Show detections by category
            if self.results['processes']:
                report_content += "SUSPICIOUS PROCESSES:\n"
                for proc in self.results['processes']:
                    confidence = proc.get('confidence', 'medium')
                    report_content += f"  - PID: {proc['pid']}, Name: {proc['name']} ({confidence.upper()})\n"
                    if proc.get('exe_path'):
                        report_content += f"    Path: {proc['exe_path']}\n"
                report_content += "\n"
            
            if self.results['java_args']:
                report_content += "SUSPICIOUS JAVA PROCESSES:\n"
                for java_proc in self.results['java_args']:
                    pattern = java_proc.get('pattern_matched', 'N/A')
                    report_content += f"  - PID: {java_proc['pid']} (Pattern: {pattern})\n"
                report_content += "\n"
            
            if self.results['files']:
                report_content += "SUSPICIOUS FILES/DIRECTORIES:\n"
                for file_info in self.results['files']:
                    confidence = file_info.get('confidence', 'medium')
                    report_content += f"  - {file_info['type'].upper()}: {file_info['path']} ({confidence.upper()})\n"
                    if file_info.get('hash'):
                        report_content += f"    Hash: {file_info['hash']}\n"
                    if file_info.get('known_version'):
                        report_content += f"    Known version: {file_info['known_version']}\n"
                report_content += "\n"
            
            if self.results['suspicious_mods']:
                report_content += "SUSPICIOUS MODS:\n"
                for mod in self.results['suspicious_mods']:
                    confidence = mod.get('confidence', 'medium')
                    report_content += f"  - JAR: {mod['jar_path']} ({confidence.upper()})\n"
                    report_content += f"    Suspicious file: {mod['suspicious_file']}\n"
                report_content += "\n"
            
            if self.results['registry']:
                report_content += "SUSPICIOUS REGISTRY ENTRIES:\n"
                for reg in self.results['registry']:
                    confidence = reg.get('confidence', 'medium')
                    report_content += f"  - {reg['key']} -> {reg['name']} ({confidence.upper()})\n"
                report_content += "\n"
            
            # Final result based on confidence
            if high_confidence > 0:
                report_content += "RESULT: DETECTED - High probability of Doomsday Client usage\n"
            else:
                report_content += "RESULT: SUSPICIOUS - Possible Doomsday Client usage (verify manually)\n"
        
        report_content += "\n" + "=" * 40 + "\n"
        
        # Save report
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_file = f"doomsday_detection_report_{timestamp}.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"Report saved to: {report_file}")
        
        return high_confidence > 0  # Return True if high confidence detections
    
    def run_full_scan(self):
        """Run complete scan"""
        print("Starting enhanced scan...")
        print("  - Checking processes...")
        self.check_running_processes()
        
        print("  - Checking filesystem...")
        self.check_filesystem()
        
        print("  - Checking Minecraft directory...")
        self.check_minecraft_directory()
        
        print("  - Checking registry...")
        self.check_registry()
        
        print("  - Generating report...")
        return self.generate_report()

def main():
    print("Doomsday Client Detector")
    print("-" * 25)
    
    detector = DoomsdayDetector()
    
    try:
        high_confidence_detection = detector.run_full_scan()
        
        if high_confidence_detection:
            print("\nRECOMMENDATION: High confidence detection - Review found items")
        else:
            print("\nScan completed")
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"\nError during scan: {e}")

if __name__ == "__main__":
    main()