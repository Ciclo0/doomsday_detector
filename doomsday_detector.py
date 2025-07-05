import os
import psutil
import winreg
import hashlib
import json
from pathlib import Path
import time

class DoomsdayDetector:
    def __init__(self):
        self.suspicious_processes = [
            'doomsday.exe',
            'doomsdayclient.exe',
            'javaw.exe',
            'java.exe'
        ]
        
        self.suspicious_files = [
            'doomsday.jar',
            'doomsdayclient.jar',
            'doomsday-client.jar'
        ]
        
        self.suspicious_dirs = [
            'doomsday',
            'doomsdayclient',
            'doomsday-client'
        ]
        
        self.minecraft_dirs = [
            os.path.expanduser('~/.minecraft'),
            os.path.expanduser('~/AppData/Roaming/.minecraft'),
            os.path.expanduser('~/AppData/Local/.minecraft')
        ]
        
        self.results = {
            'processes': [],
            'files': [],
            'registry': [],
            'network': [],
            'java_args': [],
            'suspicious_mods': []
        }
    
    def check_running_processes(self):
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_name = proc.info['name'].lower()
                cmdline = proc.info['cmdline']
                
                for suspicious in self.suspicious_processes:
                    if suspicious.lower() in proc_name:
                        self.results['processes'].append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'cmdline': cmdline
                        })
                
                if proc_name in ['java.exe', 'javaw.exe'] and cmdline:
                    cmdline_str = ' '.join(cmdline).lower()
                    if 'doomsday' in cmdline_str:
                        self.results['java_args'].append({
                            'pid': proc.info['pid'],
                            'cmdline': cmdline
                        })
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def check_filesystem(self):
        search_paths = [
            os.path.expanduser('~'),
            'C:\\Users\\Public',
            'C:\\Temp',
            'C:\\Windows\\Temp',
            os.path.expanduser('~/Downloads'),
            os.path.expanduser('~/Desktop')
        ]
        
        for search_path in search_paths:
            if os.path.exists(search_path):
                self._search_directory(search_path)
    
    def _search_directory(self, directory):
        try:
            for root, dirs, files in os.walk(directory):
                for dir_name in dirs:
                    if any(sus in dir_name.lower() for sus in self.suspicious_dirs):
                        self.results['files'].append({
                            'path': os.path.join(root, dir_name),
                            'type': 'directory'
                        })
                
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    if any(sus in file_name.lower() for sus in self.suspicious_files):
                        self.results['files'].append({
                            'path': file_path,
                            'type': 'file',
                            'size': os.path.getsize(file_path)
                        })
                    
                    if file_name.endswith('.jar'):
                        self._check_jar_file(file_path)
                        
        except PermissionError:
            pass
    
    def _check_jar_file(self, jar_path):
        try:
            import zipfile
            with zipfile.ZipFile(jar_path, 'r') as jar:
                file_list = jar.namelist()
                for file in file_list:
                    if 'doomsday' in file.lower():
                        self.results['suspicious_mods'].append({
                            'jar_path': jar_path,
                            'suspicious_file': file
                        })
        except:
            pass
    
    def check_minecraft_directory(self):
        for mc_dir in self.minecraft_dirs:
            if os.path.exists(mc_dir):
                mods_dir = os.path.join(mc_dir, 'mods')
                if os.path.exists(mods_dir):
                    self._search_directory(mods_dir)
                
                versions_dir = os.path.join(mc_dir, 'versions')
                if os.path.exists(versions_dir):
                    self._check_versions_directory(versions_dir)
                
                logs_dir = os.path.join(mc_dir, 'logs')
                if os.path.exists(logs_dir):
                    self._check_logs_directory(logs_dir)
    
    def _check_versions_directory(self, versions_dir):
        try:
            for version_folder in os.listdir(versions_dir):
                version_path = os.path.join(versions_dir, version_folder)
                if os.path.isdir(version_path):
                    if 'doomsday' in version_folder.lower():
                        self.results['files'].append({
                            'path': version_path,
                            'type': 'minecraft_version'
                        })
        except:
            pass
    
    def _check_logs_directory(self, logs_dir):
        try:
            for log_file in os.listdir(logs_dir):
                if log_file.endswith('.log'):
                    log_path = os.path.join(logs_dir, log_file)
                    try:
                        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read().lower()
                            if 'doomsday' in content:
                                self.results['files'].append({
                                    'path': log_path,
                                    'type': 'log_file',
                                    'reason': 'Contains doomsday references'
                                })
                    except:
                        pass
        except:
            pass
    
    def check_registry(self):
        try:
            import winreg
            
            registry_paths = [
                (winreg.HKEY_CURRENT_USER, r"Software"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
            ]
            
            for root_key, subkey in registry_paths:
                self._search_registry(root_key, subkey)
                
        except ImportError:
            pass
        except Exception as e:
            pass
    
    def _search_registry(self, root_key, subkey):
        try:
            with winreg.OpenKey(root_key, subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        if 'doomsday' in name.lower() or 'doomsday' in str(value).lower():
                            self.results['registry'].append({
                                'key': subkey,
                                'name': name,
                                'value': value
                            })
                        i += 1
                    except WindowsError:
                        break
        except:
            pass
    
    def check_network_connections(self):
        try:
            connections = psutil.net_connections()
            suspicious_domains = ['doomsdayclient.com', 'doomsday']
            
            for conn in connections:
                if conn.raddr:
                    pass
                    
        except:
            pass
    
    def generate_report(self):
        total_detections = (len(self.results['processes']) + 
                          len(self.results['files']) + 
                          len(self.results['registry']) + 
                          len(self.results['java_args']) + 
                          len(self.results['suspicious_mods']))
        
        # Crear reporte simplificado
        report_content = "REPORTE DE DETECCION DOOMSDAY CLIENT\n"
        report_content += "=" * 40 + "\n\n"
        
        if total_detections == 0:
            print("No se detectaron rastros de Doomsday Client")
            report_content += "RESULTADO: LIMPIO - No se detecto Doomsday Client\n"
        else:
            print(f"SE DETECTARON {total_detections} ELEMENTOS SOSPECHOSOS")
            report_content += f"SE DETECTARON {total_detections} ELEMENTOS SOSPECHOSOS\n\n"
            
            if self.results['processes']:
                report_content += "PROCESOS SOSPECHOSOS:\n"
                for proc in self.results['processes']:
                    report_content += f"  - PID: {proc['pid']}, Nombre: {proc['name']}\n"
                report_content += "\n"
            
            if self.results['java_args']:
                report_content += "PROCESOS JAVA SOSPECHOSOS:\n"
                for java_proc in self.results['java_args']:
                    report_content += f"  - PID: {java_proc['pid']}\n"
                    # Filtrar informacion sensible de los comandos
                    filtered_cmd = []
                    for cmd in java_proc['cmdline']:
                        if 'token' not in cmd.lower() and 'auth' not in cmd.lower():
                            filtered_cmd.append(cmd)
                    report_content += f"    Comandos: {' '.join(filtered_cmd)}\n"
                report_content += "\n"
            
            if self.results['files']:
                report_content += "ARCHIVOS/DIRECTORIOS SOSPECHOSOS:\n"
                for file_info in self.results['files']:
                    report_content += f"  - {file_info['type'].upper()}: {file_info['path']}\n"
                report_content += "\n"
            
            if self.results['suspicious_mods']:
                report_content += "MODS SOSPECHOSOS:\n"
                for mod in self.results['suspicious_mods']:
                    report_content += f"  - JAR: {mod['jar_path']}\n"
                    report_content += f"    Archivo sospechoso: {mod['suspicious_file']}\n"
                report_content += "\n"
            
            report_content += "RESULTADO: DETECTADO - Usuario estaba usando Doomsday Client\n"
        
        report_content += "\n" + "=" * 40 + "\n"
        report_content += "made by ciclo\n"
        
        # Guardar como archivo de texto
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_file = f"doomsday_detection_report_{timestamp}.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"Reporte guardado en: {report_file}")
    
    def run_full_scan(self):
        print("Iniciando escaneo...")
        
        self.check_running_processes()
        self.check_filesystem()
        self.check_minecraft_directory()
        self.check_registry()
        self.check_network_connections()
        
        self.generate_report()

def main():
    print("made by ciclo")
    detector = DoomsdayDetector()
    
    try:
        detector.run_full_scan()
    except KeyboardInterrupt:
        print("Escaneo interrumpido")
    except Exception as e:
        print(f"Error durante el escaneo: {e}")

if __name__ == "__main__":
    main()