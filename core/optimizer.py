import ctypes
import os
import subprocess
import psutil

if os.name == "nt":
    import winreg
else:
    winreg = None

class HardwareSystemOptimizer:
    def __init__(self):
        pass

    def unlock_ultimate_performance(self) -> tuple[bool, str]:
        if os.name != "nt":
            return False, "Только для Windows"
        try:
            guid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
            subprocess.run(["powercfg", "-setactive", guid], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return True, "Активирована схема 'Максимальная производительность'."
        except Exception as e:
            return False, str(e)

    def optimize_cpu_scheduler(self) -> tuple[bool, str]:
        if not winreg:
            return False, "Не поддерживается"
        try:
            path = r"SYSTEM\CurrentControlSet\Control\PriorityControl"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "Win32PrioritySeparation", 0, winreg.REG_DWORD, 26)
            return True, "Планировщик CPU оптимизирован."
        except Exception as e:
            return False, str(e)

    def deep_clean_ram(self) -> tuple[int, str]:
        before = psutil.virtual_memory().used
        count = 0
        if os.name == "nt":
            try:
                psapi = ctypes.windll.psapi
                kernel32 = ctypes.windll.kernel32
                for proc in psutil.process_iter(["pid"]):
                    try:
                        h = kernel32.OpenProcess(0x0400 | 0x0100, False, proc.info["pid"])
                        if h:
                            psapi.EmptyWorkingSet(h)
                            kernel32.CloseHandle(h)
                            count += 1
                    except Exception:
                        continue
            except Exception:
                pass
        freed = max(0, before - psutil.virtual_memory().used) / (1024 * 1024)
        return count, f"Оптимизировано процессов: {count}. Освобождено ОЗУ: ~{freed:.1f} МБ"

    def optimize_ssd_trim(self) -> tuple[bool, str]:
        if os.name != "nt":
            return False, "Только для Windows"
        try:
            subprocess.run(["defrag", "C:", "/L", "/O"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return True, "TRIM для диска C: выполнен."
        except Exception as e:
            return False, str(e)

    def optimize_network(self) -> tuple[bool, str]:
        if os.name != "nt":
            return False, "Только для Windows"
        try:
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(["netsh", "winsock", "reset"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return True, "Кэш DNS и Winsock сброшены."
        except Exception as e:
            return False, str(e)
