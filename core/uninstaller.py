import os
import json
import subprocess

if os.name == "nt":
    import winreg
else:
    winreg = None

from core.cleaner import format_size

class SmartUninstaller:
    def __init__(self):
        pass

    def get_installed_programs(self, include_system: bool = False) -> list[dict]:
        programs = []
        if not winreg:
            return programs
        hives = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        seen = set()
        for hive, sub_path in hives:
            try:
                with winreg.OpenKey(hive, sub_path, 0, winreg.KEY_READ) as key:
                    count = winreg.QueryInfoKey(key)[0]
                    for i in range(count):
                        try:
                            sub_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, sub_name, 0, winreg.KEY_READ) as subkey:
                                name = self._reg_val(subkey, "DisplayName")
                                if not name:
                                    continue
                                name = str(name).strip()
                                if name.lower() in seen:
                                    continue
                                seen.add(name.lower())
                                programs.append({
                                    "name": name,
                                    "publisher": str(self._reg_val(subkey, "Publisher") or "Неизвестно"),
                                    "version": str(self._reg_val(subkey, "DisplayVersion") or "-"),
                                    "uninstall_string": str(self._reg_val(subkey, "UninstallString") or ""),
                                    "install_location": str(self._reg_val(subkey, "InstallLocation") or ""),
                                })
                        except OSError:
                            continue
            except OSError:
                continue
        programs.sort(key=lambda x: x["name"].lower())
        return programs

    def get_uwp_apps(self) -> list[dict]:
        if os.name != "nt":
            return []
        try:
            ps_cmd = "Get-AppxPackage | Select-Object Name, PackageFullName | ConvertTo-Json"
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
            )
            out = res.stdout.strip()
            if not out:
                return []
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            return [{"name": item.get("Name", ""), "package_full_name": item.get("PackageFullName", "")} for item in data]
        except Exception:
            return []

    def remove_uwp_app(self, pkg: str) -> tuple[bool, str]:
        try:
            cmd = f'Remove-AppxPackage -Package "{pkg}"'
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
            )
            return res.returncode == 0, "UWP приложение удалено"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def _reg_val(key, name: str):
        try:
            val, _ = winreg.QueryValueEx(key, name)
            return val
        except OSError:
            return None
