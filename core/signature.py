import ctypes
from ctypes import wintypes
import os
import subprocess

def verify_file_signature(file_path: str) -> dict:
    result = {
        "signed": False,
        "trusted": False,
        "publisher": "Не подписан",
        "status_code": -1
    }
    if os.name != "nt" or not file_path or not os.path.exists(file_path):
        return result

    try:
        wintrust = ctypes.windll.wintrust

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", wintypes.BYTE * 8),
            ]

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.POINTER(GUID)),
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD),
            ]

        action_guid = GUID(
            0x00AAC56B, 0xCD44, 0x11D0,
            (wintypes.BYTE * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
        )
        file_info = WINTRUST_FILE_INFO(
            cbStruct=ctypes.sizeof(WINTRUST_FILE_INFO),
            pcwszFilePath=file_path,
            hFile=None,
            pgKnownSubject=None,
        )
        trust_data = WINTRUST_DATA(
            cbStruct=ctypes.sizeof(WINTRUST_DATA),
            pPolicyCallbackData=None,
            pSIPClientData=None,
            dwUIChoice=2,
            fdwRevocationChecks=0,
            dwUnionChoice=1,
            pFile=ctypes.pointer(file_info),
            dwStateAction=0,
            hWVTStateData=None,
            pwszURLReference=None,
            dwProvFlags=0x00000010,
            dwUIContext=0,
        )

        status = wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(trust_data))
        result["status_code"] = status

        if status == 0:
            result["signed"] = True
            result["trusted"] = True
            result["publisher"] = _extract_publisher_name(file_path)
        elif status == 0x800B0100:
            result["publisher"] = "Цифровая подпись отсутствует"
        else:
            result["signed"] = True
            result["trusted"] = False
            result["publisher"] = f"Недоверенная подпись (0x{status & 0xFFFFFFFF:X})"
    except Exception as e:
        result["publisher"] = f"Ошибка: {e}"

    return result

def _extract_publisher_name(file_path: str) -> str:
    try:
        cmd = f'(Get-AuthenticodeSignature "{file_path}").SignerCertificate.Subject'
        res = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        subj = res.stdout.strip()
        if "CN=" in subj:
            cn_part = subj.split("CN=")[1]
            if cn_part.startswith('"'):
                return cn_part.split('"')[1]
            return cn_part.split(",")[0].strip()
        return subj or "Издатель проверен"
    except Exception:
        return "Издатель проверен"
