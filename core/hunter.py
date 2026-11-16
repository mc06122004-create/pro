import os
import re
import subprocess
import psutil

if os.name == "nt":
    import winreg
else:
    winreg = None

from core.privileges import take_ownership_and_unlock, run_as_trusted_installer
from core.signature import verify_file_signature
from core.quarantine import QuarantineManager

SYSTEM_PROCESS_PATHS = {
    "svchost.exe": [r"c:\windows\system32", r"c:\windows\syswow64"],
    "csrss.exe": [r"c:\windows\system32"],
    "wininit.exe": [r"c:\windows\system32"],
    "winlogon.exe": [r"c:\windows\system32"],
    "lsass.exe": [r"c:\windows\system32"],
    "services.exe": [r"c:\windows\system32"],
    "smss.exe": [r"c:\windows\system32"],
    "taskhostw.exe": [r"c:\windows\system32"],
    "explorer.exe": [r"c:\windows"],
    "dwm.exe": [r"c:\windows\system32"],
    "conhost.exe": [r"c:\windows\system32"],
    "runtimebroker.exe": [r"c:\windows\system32"],
    "spoolsv.exe": [r"c:\windows\system32"],
    "ctfmon.exe": [r"c:\windows\system32", r"c:\windows\syswow64"],
}

INJECTION_TARGETS = {"regasm.exe", "installutil.exe", "aspnet_compiler.exe", "msbuild.exe"}
SUSPICIOUS_DIRS = [r"\appdata\local\temp", r"\appdata\roaming", r"\programdata", r"\users\public", r"\windows\temp"]
MINER_PATTERNS = [r"xmrig", r"minerd", r"cgminer", r"stratum\+tcp", r"--donate-level", r"realtekhd", r"soundmixer", r"winserv\.exe"]
TRUSTED_SUBFOLDERS = [r"\microsoft\\", r"\google\\", r"\discord\\", r"\steam\\", r"\nvidia\\", r"\amd\\", r"\telegram desktop\\"]

class ThreatHunter:
    def __init__(self):
        self.qm = QuarantineManager()
        self._sig_cache = {}

    def _get_sig(self, path: str) -> dict:
        if not path:
            return {"signed": False, "trusted": False, "publisher": "Нет пути"}
        norm = path.lower()
        if norm not in self._sig_cache:
            self._sig_cache[norm] = verify_file_signature(path)
        return self._sig_cache[norm]

    def scan_processes(self) -> list[dict]:
        threats = []
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                pid = proc.info["pid"]
                if pid <= 4:
                    continue
                name = (proc.info["name"] or "").lower()
                exe_path = proc.info["exe"] or ""
                if not exe_path or self.qm.is_whitelisted(exe_path):
                    continue

                exe_lower = exe_path.lower()
                exe_dir = os.path.dirname(exe_lower)
                cmdline = " ".join(proc.info["cmdline"] or [])
                cmd_lower = cmdline.lower()

                if name in SYSTEM_PROCESS_PATHS:
                    allowed = SYSTEM_PROCESS_PATHS[name]
                    sig = self._get_sig(exe_path)
                    if exe_dir not in allowed or not sig["trusted"]:
                        threats.append({
                            "id": f"PROC_SPOOF_{pid}", "type": "PROCESS",
                            "category": "Подмена системного процесса", "severity": "КРИТИЧНО",
                            "name": proc.info["name"], "target": exe_path, "pid": pid,
                            "details": f"Путь: {exe_dir} | Подпись: {sig['publisher']}"
                        })
                        continue

                if any(re.search(pat, name) or re.search(pat, cmd_lower) for pat in MINER_PATTERNS):
                    threats.append({
                        "id": f"PROC_MINER_{pid}", "type": "PROCESS",
                        "category": "Криптомайнер / Вредонос", "severity": "КРИТИЧНО",
                        "name": proc.info["name"], "target": exe_path, "pid": pid,
                        "details": f"Сигнатура/Аргументы: {cmdline[:80]}"
                    })
                    continue

                if any(s_dir in exe_dir for s_dir in SUSPICIOUS_DIRS):
                    if not any(tf in exe_lower for tf in TRUSTED_SUBFOLDERS):
                        sig = self._get_sig(exe_path)
                        if not sig["trusted"]:
                            threats.append({
                                "id": f"PROC_SUSP_{pid}", "type": "PROCESS",
                                "category": "Подозрительный процесс в скрытой папке", "severity": "ВЫСОКИЙ",
                                "name": proc.info["name"], "target": exe_path, "pid": pid,
                                "details": f"Подпись: {sig['publisher']}"
                            })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return threats

    def scan_registry_persistence(self) -> list[dict]:
        findings = []
        if not winreg:
            return findings
        run_locations = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
        ]
        for hive, path, hname in run_locations:
            try:
                with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            vname, vdata, _ = winreg.EnumValue(key, i)
                            i += 1
                            cmd_str = str(vdata)
                            lower_cmd = cmd_str.lower()
                            if any(sd in lower_cmd for sd in SUSPICIOUS_DIRS) or any(ext in lower_cmd for ext in [".vbs", ".bat", ".ps1"]):
                                findings.append({
                                    "id": f"REG_RUN_{hname}_{vname}", "type": "REG_VALUE",
                                    "category": "Подозрительная автозагрузка", "severity": "ВЫСОКИЙ",
                                    "name": vname, "target": cmd_str,
                                    "reg_hive": hive, "reg_path": path, "reg_val": vname,
                                    "details": f"[{hname}] Команда: {cmd_str[:80]}"
                                })
                        except OSError:
                            break
            except OSError:
                continue
        return findings

    def run_full_scan(self) -> list[dict]:
        res = []
        res.extend(self.scan_processes())
        res.extend(self.scan_registry_persistence())
        return res

    def neutralize_threat(self, threat: dict) -> tuple[bool, str]:
        t_type = threat.get("type", "")
        target = threat.get("target", "")
        try:
            if t_type == "PROCESS":
                pid = threat.get("pid")
                if pid:
                    try:
                        p = psutil.Process(pid)
                        p.kill()
                    except Exception:
                        pass
                if target and os.path.exists(target):
                    self.qm.quarantine_file(target, threat.get("category", "Угроза"))
                return True, "Процесс нейтрализован"
            elif t_type == "REG_VALUE":
                with winreg.OpenKey(threat["reg_hive"], threat["reg_path"], 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, threat["reg_val"])
                return True, "Ключ автозагрузки удален"
        except Exception as e:
            return False, str(e)
        return False, "Неизвестный тип"
