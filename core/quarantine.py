import hashlib
import json
import os
import time
import uuid

from core.privileges import take_ownership_and_unlock

QUARANTINE_DIR = os.path.join(os.environ.get("PROGRAMDATA", "C:\ProgramData"), "SystemPurgePro", "Quarantine")
INDEX_FILE = os.path.join(QUARANTINE_DIR, "index.json")
WHITELIST_FILE = os.path.join(os.environ.get("PROGRAMDATA", "C:\ProgramData"), "SystemPurgePro", "whitelist.json")
XOR_KEY = 0x5A

class QuarantineManager:
    def __init__(self):
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        if not os.path.exists(INDEX_FILE):
            self._save_index({})
        if not os.path.exists(WHITELIST_FILE):
            self._save_whitelist([])

    def _load_index(self) -> dict:
        try:
            with open(INDEX_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_index(self, data: dict):
        with open(INDEX_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def get_whitelist(self) -> list[str]:
        try:
            with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _save_whitelist(self, items: list[str]):
        with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
            json.dump(items, f, indent=2, ensure_ascii=False)

    def add_to_whitelist(self, path: str):
        wl = self.get_whitelist()
        norm = os.path.normpath(path).lower()
        if norm not in wl:
            wl.append(norm)
            self._save_whitelist(wl)

    def is_whitelisted(self, path: str) -> bool:
        if not path:
            return False
        norm = os.path.normpath(path).lower()
        for entry in self.get_whitelist():
            if norm == entry or norm.startswith(entry + os.sep):
                return True
        return False

    @staticmethod
    def _xor_transform(src_path: str, dst_path: str):
        with open(src_path, "rb") as f_in, open(dst_path, "wb") as f_out:
            while chunk := f_in.read(65536):
                transformed = bytes(b ^ XOR_KEY for b in chunk)
                f_out.write(transformed)

    @staticmethod
    def _calc_sha256(file_path: str) -> str:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def quarantine_file(self, file_path: str, reason: str) -> tuple[bool, str]:
        if not os.path.exists(file_path):
            return False, "Файл не найден"
        if self.is_whitelisted(file_path):
            return False, "Файл в белом списке"
        try:
            take_ownership_and_unlock(file_path)
            item_id = str(uuid.uuid4())[:8]
            vault_path = os.path.join(QUARANTINE_DIR, f"{item_id}.qvault")
            file_hash = self._calc_sha256(file_path)

            self._xor_transform(file_path, vault_path)
            os.chmod(file_path, 0o777)
            os.remove(file_path)

            index = self._load_index()
            index[item_id] = {
                "id": item_id,
                "original_path": file_path,
                "vault_path": vault_path,
                "sha256": file_hash,
                "reason": reason,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._save_index(index)
            return True, f"Файл помещен в карантин (ID: {item_id})"
        except Exception as e:
            return False, f"Ошибка карантина: {e}"

    def restore_file(self, item_id: str) -> tuple[bool, str]:
        index = self._load_index()
        entry = index.get(item_id)
        if not entry:
            return False, "Запись не найдена"
        try:
            orig_path = entry["original_path"]
            vault_path = entry["vault_path"]
            os.makedirs(os.path.dirname(orig_path), exist_ok=True)
            self._xor_transform(vault_path, orig_path)
            os.remove(vault_path)
            del index[item_id]
            self._save_index(index)
            return True, f"Восстановлено: {orig_path}"
        except Exception as e:
            return False, f"Ошибка восстановления: {e}"
