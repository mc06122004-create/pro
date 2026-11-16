import os
import shutil
import subprocess
import tempfile
import time

from core.quarantine import QuarantineManager

def format_size(bytes_val: int) -> str:
    if bytes_val <= 0:
        return "0.00 Б"
    for unit in ["Б", "КБ", "МБ", "ГБ", "ТБ"]:
        if bytes_val < 1024:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.2f} ПБ"

class DeepDiskCleaner:
    def __init__(self):
        self.qm = QuarantineManager()
        self.local_app = os.environ.get("LOCALAPPDATA", "")
        self.win_dir = os.environ.get("WINDIR", r"C:\Windows")
        self.sys_drive = os.environ.get("SystemDrive", "C:") + "\\"
        self.user_temp = tempfile.gettempdir()

    def get_clean_categories(self) -> dict:
        return {
            "Временные файлы (Temp & Prefetch)": {
                "paths": [self.user_temp, os.path.join(self.win_dir, "Temp"), os.path.join(self.win_dir, "Prefetch")]
            },
            "Кэш обновлений Windows": {
                "paths": [os.path.join(self.win_dir, "SoftwareDistribution", "Download")]
            },
            "Кэш браузеров (Chrome, Edge, Yandex, Opera)": {
                "paths": [
                    os.path.join(self.local_app, "Google", "Chrome", "User Data", "Default", "Cache"),
                    os.path.join(self.local_app, "Microsoft", "Edge", "User Data", "Default", "Cache"),
                    os.path.join(self.local_app, "Yandex", "YandexBrowser", "User Data", "Default", "Cache"),
                ]
            },
            "Кэш шейдеров GPU (DirectX / NVIDIA / AMD)": {
                "paths": [
                    os.path.join(self.local_app, "D3DSCache"),
                    os.path.join(self.local_app, "NVIDIA", "DXCache"),
                    os.path.join(self.local_app, "AMD", "DxCache"),
                ]
            }
        }

    def scan_junk(self) -> dict:
        cats = self.get_clean_categories()
        report = {}
        total_b = 0
        total_f = 0
        for name, cfg in cats.items():
            cb = 0
            cf = 0
            for bp in cfg["paths"]:
                if bp and os.path.exists(bp):
                    for r, _, fs in os.walk(bp):
                        for f in fs:
                            fp = os.path.join(r, f)
                            try:
                                cb += os.path.getsize(fp)
                                cf += 1
                            except OSError:
                                continue
            report[name] = {"bytes": cb, "size_str": format_size(cb), "files_count": cf}
            total_b += cb
            total_f += cf
        return {"categories": report, "total_bytes": total_b, "total_size_str": format_size(total_b), "total_files": total_f}

    def clean_junk(self) -> tuple[int, int]:
        cats = self.get_clean_categories()
        freed = 0
        count = 0
        for _, cfg in cats.items():
            for bp in cfg["paths"]:
                if bp and os.path.exists(bp):
                    for item in os.listdir(bp):
                        ip = os.path.join(bp, item)
                        try:
                            if os.path.isfile(ip) or os.path.islink(ip):
                                sz = os.path.getsize(ip)
                                os.remove(ip)
                                freed += sz
                                count += 1
                            elif os.path.isdir(ip):
                                shutil.rmtree(ip, ignore_errors=True)
                                count += 1
                        except Exception:
                            continue
        return freed, count

    def run_dism_winsxs_cleanup(self) -> tuple[bool, str]:
        if os.name != "nt":
            return False, "Только для Windows"
        try:
            res = subprocess.run(
                ["Dism.exe", "/online", "/Cleanup-Image", "/StartComponentCleanup", "/ResetBase"],
                capture_output=True, text=True, encoding="cp866", errors="ignore",
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if res.returncode == 0:
                return True, "Хранилище WinSxS очищено."
            return False, f"Код ошибки DISM: {res.returncode}"
        except Exception as e:
            return False, str(e)
