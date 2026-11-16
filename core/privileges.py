import ctypes
import os
import subprocess
import sys

if os.name == "nt":
    import win32api
    import win32security

REQUIRED_PRIVILEGES = [
    "SeDebugPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeRestorePrivilege",
    "SeBackupPrivilege",
    "SeShutdownPrivilege",
    "SeLoadDriverPrivilege",
]

def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def elevate_to_admin() -> None:
    if os.name != "nt":
        return
    if not is_admin():
        script = os.path.abspath(sys.argv[0])
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        cmd = f'"{script}" {params}'.strip()
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, cmd, None, 1)
        sys.exit(0)

def enable_all_privileges() -> dict[str, bool]:
    results = {priv: False for priv in REQUIRED_PRIVILEGES}
    if os.name != "nt":
        return results
    try:
        flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
        htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(), flags)
        for priv_name in REQUIRED_PRIVILEGES:
            try:
                priv_id = win32security.LookupPrivilegeValue(None, priv_name)
                win32security.AdjustTokenPrivileges(
                    htoken, False, [(priv_id, win32security.SE_PRIVILEGE_ENABLED)]
                )
                results[priv_name] = (win32api.GetLastError() == 0)
            except Exception:
                results[priv_name] = False
        win32api.CloseHandle(htoken)
    except Exception:
        pass
    return results

def take_ownership_and_unlock(target_path: str) -> bool:
    if os.name != "nt" or not os.path.exists(target_path):
        return False
    try:
        is_dir = os.path.isdir(target_path)
        takeown_cmd = ["takeown", "/f", target_path, "/a"]
        icacls_cmd = ["icacls", target_path, "/grant", "Administrators:F", "/c", "/q"]
        if is_dir:
            takeown_cmd.extend(["/r", "/d", "y"])
            icacls_cmd.append("/t")
        subprocess.run(takeown_cmd, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(icacls_cmd, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        return True
    except Exception:
        return False

def run_as_trusted_installer(command: str) -> tuple[bool, str]:
    if os.name != "nt":
        return False, "Доступно только в Windows"
    try:
        subprocess.run(["sc", "start", "TrustedInstaller"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        ps_script = f'''
        $ti = Get-Process -Name TrustedInstaller -ErrorAction SilentlyContinue
        if (-not $ti) {{ Start-Service TrustedInstaller; Start-Sleep -Milliseconds 500 }}
        cmd.exe /c "{command}"
        '''
        res = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        return res.returncode == 0, res.stdout.strip() or res.stderr.strip()
    except Exception as e:
        return False, str(e)
