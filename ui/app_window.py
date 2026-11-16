import threading
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
import psutil

from core.privileges import is_admin, enable_all_privileges
from core.cleaner import DeepDiskCleaner, format_size
from core.hunter import ThreatHunter
from core.uninstaller import SmartUninstaller
from core.optimizer import HardwareSystemOptimizer

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class SystemPurgeApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SystemPurge Pro — Профессиональный оптимизатор и защитник Windows")
        self.geometry("1100x700")
        self.minsize(980, 620)

        enable_all_privileges()

        self.hunter = ThreatHunter()
        self.cleaner = DeepDiskCleaner()
        self.uninstaller = SmartUninstaller()
        self.optimizer = HardwareSystemOptimizer()

        self._build_layout()
        self._update_stats()

    def _build_layout(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        sidebar = ctk.CTkFrame(self, width=240, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_rowconfigure(6, weight=1)

        ctk.CTkLabel(
            sidebar, text="SYSTEMPURGE PRO",
            font=ctk.CTkFont(size=18, weight="bold")
        ).grid(row=0, column=0, padx=20, pady=(24, 6), sticky="w")

        adm_text = "ПРАВА: АДМИНИСТРАТОР" if is_admin() else "ПРАВА: ПОЛЬЗОВАТЕЛЬ"
        adm_color = "#2ecc71" if is_admin() else "#e74c3c"
        ctk.CTkLabel(
            sidebar, text=adm_text, text_color=adm_color,
            font=ctk.CTkFont(size=11, weight="bold")
        ).grid(row=1, column=0, padx=20, pady=(0, 20), sticky="w")

        nav_items = [
            ("dashboard", "Обзор и Автозачистка"),
            ("hunter", "Анти-Майнер и Угрозы"),
            ("cleaner", "Очистка диска"),
            ("programs", "Менеджер программ"),
            ("optimizer", "Аппаратный Тюнинг"),
        ]

        self.nav_buttons = {}
        for idx, (key, text) in enumerate(nav_items, start=2):
            btn = ctk.CTkButton(
                sidebar, text=text, height=40, anchor="w",
                fg_color="transparent", text_color=("gray10", "gray90"),
                hover_color=("gray70", "gray25"),
                command=lambda k=key: self.show_frame(k)
            )
            btn.grid(row=idx, column=0, padx=12, pady=4, sticky="ew")
            self.nav_buttons[key] = btn

        self.sys_stat_lbl = ctk.CTkLabel(
            sidebar, text="CPU: 0% | RAM: 0%",
            font=ctk.CTkFont(size=12), text_color="gray70"
        )
        self.sys_stat_lbl.grid(row=7, column=0, padx=15, pady=15, sticky="w")

        self.container = ctk.CTkFrame(self, corner_radius=10, fg_color="transparent")
        self.container.grid(row=0, column=1, padx=16, pady=16, sticky="nsew")
        self.container.grid_columnconfigure(0, weight=1)
        self.container.grid_rowconfigure(0, weight=1)

        self.frames = {}
        self._create_dashboard()
        self._create_hunter_ui()
        self._create_cleaner_ui()
        self._create_programs_ui()
        self._create_optimizer_ui()

        self.show_frame("dashboard")

    def show_frame(self, key: str):
        for k, btn in self.nav_buttons.items():
            btn.configure(fg_color=("gray75", "gray25") if k == key else "transparent")
        for f in self.frames.values():
            f.grid_forget()
        self.frames[key].grid(row=0, column=0, sticky="nsew")

    def _update_stats(self):
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        self.sys_stat_lbl.configure(text=f"CPU: {cpu:.0f}%  |  RAM: {ram:.0f}%")
        self.after(2000, self._update_stats)

    def _create_dashboard(self):
        frame = ctk.CTkFrame(self.container)
        self.frames["dashboard"] = frame
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(frame, text="Центр управления и защиты", font=ctk.CTkFont(size=22, weight="bold")).grid(row=0, column=0, padx=20, pady=(20, 8), sticky="w")
        ctk.CTkLabel(frame, text="Полный комплекс: поиск скрытых майнеров, глубокая очистка диска и ускорение железа.", text_color="gray75").grid(row=1, column=0, padx=20, pady=(0, 15), sticky="w")

        self.dash_log = ctk.CTkTextbox(frame, font=ctk.CTkFont(family="Consolas", size=12))
        self.dash_log.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")
        self._log(self.dash_log, "Готово к работе. Нажмите кнопку полной автозачистки.")

        btn_bar = ctk.CTkFrame(frame, fg_color="transparent")
        btn_bar.grid(row=3, column=0, padx=20, pady=18, sticky="ew")

        ctk.CTkButton(btn_bar, text="ПОЛНАЯ АВТОЗАЧИСТКА И ТЮНИНГ", height=42, fg_color="#c0392b", hover_color="#962d22", font=ctk.CTkFont(size=14, weight="bold"), command=self._run_auto_purge).pack(side="left")

    def _run_auto_purge(self):
        if not messagebox.askyesno("Подтверждение", "Запустить полную автозачистку угроз, мусора и оптимизацию системы?"):
            return
        def task():
            self._log(self.dash_log, "\n=== СТАРТ ПОЛНОЙ АВТОЗАЧИСТКИ ===")
            threats = self.hunter.run_full_scan()
            for t in threats:
                _, msg = self.hunter.neutralize_threat(t)
                self._log(self.dash_log, f"[УГРОЗА] {msg}")

            freed, count = self.cleaner.clean_junk()
            self._log(self.dash_log, f"[ДИСК] Очищено {format_size(freed)} (файлов: {count})")

            _, ram_msg = self.optimizer.deep_clean_ram()
            self._log(self.dash_log, f"[ОЗУ] {ram_msg}")

            self._log(self.dash_log, "=== АВТОЗАЧИСТКА УСПЕШНО ЗАВЕРШЕНА ===")
        threading.Thread(target=task, daemon=True).start()

    def _create_hunter_ui(self):
        frame = ctk.CTkFrame(self.container)
        self.frames["hunter"] = frame
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        ctk.CTkLabel(top, text="Анти-Майнер и Детектор Угроз", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        ctk.CTkButton(top, text="Сканировать систему", command=self._scan_threats).pack(side="right")

        self.hunter_scroll = ctk.CTkScrollableFrame(frame)
        self.hunter_scroll.grid(row=1, column=0, padx=20, pady=15, sticky="nsew")
        self.hunter_scroll.grid_columnconfigure(0, weight=1)

    def _scan_threats(self):
        for w in self.hunter_scroll.winfo_children():
            w.destroy()
        def task():
            threats = self.hunter.run_full_scan()
            self.after(0, lambda: self._render_threats(threats))
        threading.Thread(target=task, daemon=True).start()

    def _render_threats(self, threats: list[dict]):
        for w in self.hunter_scroll.winfo_children():
            w.destroy()
        if not threats:
            ctk.CTkLabel(self.hunter_scroll, text="Угроз и подменных процессов не обнаружено.", text_color="#2ecc71", font=ctk.CTkFont(size=14)).pack(pady=30)
            return
        for idx, t in enumerate(threats):
            card = ctk.CTkFrame(self.hunter_scroll)
            card.grid(row=idx, column=0, pady=6, padx=6, sticky="ew")
            card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(card, text=f"[{t['severity']}] {t['category']}: {t['name']}", font=ctk.CTkFont(size=13, weight="bold"), text_color="#e74c3c").grid(row=0, column=0, padx=12, pady=(8, 2), sticky="w")
            ctk.CTkLabel(card, text=f"Цель: {t['target']}\nДетали: {t['details']}", font=ctk.CTkFont(size=11), justify="left", text_color="gray80").grid(row=1, column=0, padx=12, pady=(0, 8), sticky="w")
            ctk.CTkButton(card, text="Уничтожить", width=110, fg_color="#c0392b", command=lambda item=t: self._neutralize(item)).grid(row=0, column=1, rowspan=2, padx=12)

    def _neutralize(self, t: dict):
        ok, msg = self.hunter.neutralize_threat(t)
        messagebox.showinfo("Результат", msg)
        self._scan_threats()

    def _create_cleaner_ui(self):
        frame = ctk.CTkFrame(self.container)
        self.frames["cleaner"] = frame
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        ctk.CTkLabel(top, text="Глубокая очистка диска", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        ctk.CTkButton(top, text="Очистить мусор", fg_color="#27ae60", command=self._clean_disk).pack(side="right", padx=(10, 0))
        ctk.CTkButton(top, text="Анализировать", command=self._scan_disk).pack(side="right")

        self.cleaner_box = ctk.CTkTextbox(frame, font=ctk.CTkFont(family="Consolas", size=13))
        self.cleaner_box.grid(row=1, column=0, padx=20, pady=15, sticky="nsew")

    def _scan_disk(self):
        self.cleaner_box.delete("1.0", "end")
        self._log(self.cleaner_box, "Сканирование мусора на диске...")
        def task():
            res = self.cleaner.scan_junk()
            self.after(0, lambda: self._display_clean_res(res))
        threading.Thread(target=task, daemon=True).start()

    def _display_clean_res(self, res: dict):
        self.cleaner_box.delete("1.0", "end")
        for cat, info in res["categories"].items():
            self._log(self.cleaner_box, f"• {cat}: {info['size_str']} ({info['files_count']} файлов)")
        self._log(self.cleaner_box, f"\nВСЕГО МУСОРА: {res['total_size_str']}")

    def _clean_disk(self):
        def task():
            freed, count = self.cleaner.clean_junk()
            self.after(0, lambda: self._log(self.cleaner_box, f"\n[ОЧИЩЕНО] Освобождено: {format_size(freed)} (удалено объектов: {count})"))
        threading.Thread(target=task, daemon=True).start()

    def _create_programs_ui(self):
        frame = ctk.CTkFrame(self.container)
        self.frames["programs"] = frame
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        ctk.CTkLabel(top, text="Менеджер программ и UWP Bloatware", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        ctk.CTkButton(top, text="Сканировать ПО", command=self._load_progs).pack(side="right")

        self.prog_scroll = ctk.CTkScrollableFrame(frame)
        self.prog_scroll.grid(row=1, column=0, padx=20, pady=15, sticky="nsew")
        self.prog_scroll.grid_columnconfigure(0, weight=1)

    def _load_progs(self):
        for w in self.prog_scroll.winfo_children():
            w.destroy()
        def task():
            progs = self.uninstaller.get_installed_programs()
            self.after(0, lambda: self._render_progs(progs))
        threading.Thread(target=task, daemon=True).start()

    def _render_progs(self, progs: list[dict]):
        for w in self.prog_scroll.winfo_children():
            w.destroy()
        for idx, p in enumerate(progs):
            row = ctk.CTkFrame(self.prog_scroll)
            row.grid(row=idx, column=0, pady=4, padx=4, sticky="ew")
            row.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(row, text=f"{p['name']} (v{p['version']}) — {p['publisher']}", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")

    def _create_optimizer_ui(self):
        frame = ctk.CTkFrame(self.container)
        self.frames["optimizer"] = frame
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(frame, text="Аппаратный тюнинг и оптимизация железа", font=ctk.CTkFont(size=20, weight="bold")).grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")
        
        btn_grid = ctk.CTkFrame(frame, fg_color="transparent")
        btn_grid.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        ctk.CTkButton(btn_grid, text="Максимальная производительность (CPU)", height=40, command=lambda: self._opt_action(self.optimizer.unlock_ultimate_performance())).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btn_grid, text="Глубокая очистка ОЗУ", height=40, command=lambda: self._opt_action(self.optimizer.deep_clean_ram())).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btn_grid, text="Оптимизация SSD (TRIM)", height=40, command=lambda: self._opt_action(self.optimizer.optimize_ssd_trim())).pack(side="left")

        self.opt_log_box = ctk.CTkTextbox(frame, font=ctk.CTkFont(family="Consolas", size=12))
        self.opt_log_box.grid(row=2, column=0, padx=20, pady=15, sticky="nsew")

    def _opt_action(self, res):
        if isinstance(res, tuple):
            _, msg = res
            self._log(self.opt_log_box, f"[ТЮНИНГ] {msg}")
        else:
            self._log(self.opt_log_box, f"[ТЮНИНГ] {res}")

    @staticmethod
    def _log(box: ctk.CTkTextbox, text: str):
        box.insert("end", text + "\n")
        box.see("end")
