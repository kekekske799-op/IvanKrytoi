#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Analyzer — анализ и автолечение системы.
Запуск: python 2.py   (лучше от имени администратора)
"""

import sys, subprocess, importlib

# ---------- авто-установка psutil ----------
def _ensure(mod, pkg):
    try:
        importlib.import_module(mod)
        return
    except ImportError:
        pass
    print(f"[*] Устанавливаю {pkg}...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install",
                               "--disable-pip-version-check", pkg])
        importlib.invalidate_caches()
    except Exception as e:
        print(f"[✗] Не удалось установить {pkg}: {e}")
        input("Enter для выхода...")
        sys.exit(1)

_ensure("psutil", "psutil")

# ---------- импорты ----------
import os, json, socket, platform, datetime, threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import psutil

# ---------- цвета ----------
BG      = "#0f1420"
CARD    = "#1a2233"
CARD2   = "#232d42"
FG      = "#e6edf7"
FG2     = "#8b9bb4"
ACCENT  = "#4f8cff"
ACCENT2 = "#7c5cff"
GREEN   = "#28c76f"
YELLOW  = "#ffb020"
RED     = "#ff4d4f"

# ---------- админ? ----------
def is_admin():
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False

IS_ADMIN = is_admin()

# ---------- реестр фиксов ----------
FIXES = {}

def fix_disable_smbv1():
    subprocess.check_call(
        'powershell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"',
        shell=True)
    return "SMBv1 отключён"

def fix_enable_uac():
    subprocess.check_call(
        'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" '
        '/v EnableLUA /t REG_DWORD /d 1 /f', shell=True)
    return "UAC включён (нужна перезагрузка)"

def fix_enable_firewall():
    subprocess.check_call('netsh advfirewall set allprofiles state on', shell=True)
    return "Firewall включён"

def fix_enable_rtp():
    subprocess.check_call(
        'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"',
        shell=True)
    return "Defender RTP включена"

def fix_ufw():
    subprocess.check_call(["ufw", "--force", "enable"])
    return "UFW включён"

def fix_manual():
    raise RuntimeError("Эту проблему нужно устранить вручную")

FIXES.update({
    "smbv1":     ("Отключить SMBv1",                   fix_disable_smbv1),
    "uac":       ("Включить UAC",                      fix_enable_uac),
    "firewall":  ("Включить Windows Firewall",         fix_enable_firewall),
    "defender":  ("Включить Defender Real-Time",       fix_enable_rtp),
    "ufw":       ("Включить UFW",                      fix_ufw),
    "manual":    ("Ручное исправление",                fix_manual),
})

# ---------- данные отчёта ----------
REPORT = {"timestamp": "", "system": {}, "findings": [], "score": 100}

def add(level, category, message, fix_id="manual"):
    REPORT["findings"].append({
        "level": level, "category": category,
        "message": message, "fix_id": fix_id,
    })
    if level == "CRIT":
        REPORT["score"] -= 10
    elif level == "WARN":
        REPORT["score"] -= 3
    REPORT["score"] = max(0, REPORT["score"])

def log_cb_factory(cb):
    def _log(level, msg):
        if cb: cb(level, msg)
    return _log

# ---------- проверки ----------
def check_os(log):
    log("info", "Проверка ОС...")
    REPORT["system"] = {
        "os": platform.system(),
        "release": platform.release(),
        "arch": platform.machine(),
        "hostname": socket.gethostname(),
    }
    log("ok", f"ОС: {platform.system()} {platform.release()} ({platform.machine()})")
    if platform.system() == "Windows":
        try:
            v = sys.getwindowsversion()
            if v.build < 19041:
                add("WARN", "OS", f"Устаревший Windows build {v.build}")
                log("warn", f"Устаревший build Windows: {v.build}")
            else:
                add("OK", "OS", "Актуальная ветка Windows")
                log("ok", f"Windows build {v.build} — ок")
        except Exception:
            pass
    elif platform.system() == "Linux":
        log("info", f"Ядро: {platform.uname().release}")
        try:
            if os.path.exists("/etc/os-release"):
                data = open("/etc/os-release").read()
                if "Ubuntu" in data and ("16.04" in data or "18.04" in data):
                    add("CRIT", "OS", "Ubuntu EOL")
                    log("crit", "Ubuntu EOL — обновлений нет!")
                else:
                    add("OK", "OS", "ОС поддерживается")
                    log("ok", "ОС подходит")
        except Exception:
            pass

def check_users(log):
    log("info", "Проверка пользователей...")
    if platform.system() == "Windows":
        try:
            out = subprocess.check_output("net user", shell=True,
                                          text=True, errors="ignore")
            lines = out.splitlines()
            users, started = [], False
            for line in lines:
                s = line.strip()
                if "---" in s:
                    started = not started
                    continue
                if started and s:
                    users.extend(s.split())
            log("info", f"Найдено пользователей: {len(users)}")
            for u in users:
                try:
                    d = subprocess.check_output(
                        f'net user "{u}"', shell=True, text=True, errors="ignore")
                    if "Password required" in d and \
                       "No" in d.split("Password required")[1][:20]:
                        add("CRIT", "Users", f"'{u}' без пароля", "manual")
                        log("crit", f"'{u}' без пароля!")
                    if "Account active" in d and \
                       "No" in d.split("Account active")[1][:15]:
                        add("WARN", "Users", f"'{u}' отключён", "manual")
                        log("warn", f"'{u}' отключён")
                except Exception:
                    pass
        except Exception as e:
            log("warn", f"Ошибка: {e}")
    else:
        try:
            import pwd
            for u in pwd.getpwall():
                if u.pw_uid == 0 and u.pw_name != "root":
                    add("CRIT", "Users", f"UID 0 у {u.pw_name}", "manual")
                    log("crit", f"UID 0 у '{u.pw_name}'!")
            try:
                for line in open("/etc/shadow"):
                    p = line.strip().split(":")
                    if len(p) > 1 and p[1] == "":
                        add("CRIT", "Users", f"{p[0]} без пароля", "manual")
                        log("crit", f"'{p[0]}' без пароля!")
            except PermissionError:
                log("warn", "Нет root — /etc/shadow пропущен")
        except Exception as e:
            log("warn", f"Ошибка: {e}")
    log("ok", "Пользователи проверены")

def check_net(log):
    log("info", "Проверка портов...")
    dangerous = {21:"FTP", 23:"Telnet", 25:"SMTP", 135:"RPC", 139:"NetBIOS",
                 445:"SMB", 1433:"MSSQL", 3306:"MySQL", 3389:"RDP",
                 5900:"VNC", 6379:"Redis", 27017:"MongoDB"}
    try:
        listeners = set()
        for c in psutil.net_connections(kind="inet"):
            if c.status == psutil.CONN_LISTEN:
                listeners.add((c.laddr.port, c.laddr.ip))
        if not listeners:
            log("ok", "Портов в прослушке нет")
        for port, ip in sorted(listeners):
            if port in dangerous:
                add("WARN", "Network", f"Порт {port} ({dangerous[port]})", "manual")
                log("warn", f"{ip}:{port} ({dangerous[port]})")
            else:
                log("info", f"{ip}:{port}")
    except Exception as e:
        log("warn", f"Порты: {e}")

    sysname = platform.system()
    if sysname == "Windows":
        try:
            out = subprocess.check_output(
                "netsh advfirewall show allprofiles state",
                shell=True, text=True, errors="ignore")
            if "ON" in out.upper() or "ВКЛ" in out.upper():
                add("OK", "Firewall", "Firewall включён")
                log("ok", "Windows Firewall активен")
            else:
                add("CRIT", "Firewall", "Firewall выключен", "firewall")
                log("crit", "Windows Firewall ВЫКЛЮЧЕН!")
        except Exception:
            pass
    else:
        try:
            out = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
            if "active" in out.stdout.lower():
                add("OK", "Firewall", "UFW активен")
                log("ok", "UFW активен")
            else:
                add("WARN", "Firewall", "UFW неактивен", "ufw")
                log("warn", "UFW неактивен")
        except Exception:
            pass

def check_protection(log):
    log("info", "Проверка защиты...")
    if platform.system() == "Windows":
        try:
            out = subprocess.check_output(
                'powershell -Command "(Get-MpComputerStatus).RealTimeProtectionEnabled"',
                shell=True, text=True, errors="ignore", timeout=15)
            if "True" in out:
                add("OK", "Antivirus", "Defender активен")
                log("ok", "Defender RTP активна")
            else:
                add("WARN", "Antivirus", "Defender RTP выкл", "defender")
                log("warn", "Defender RTP выключена")
        except Exception:
            log("warn", "Defender: не удалось проверить")

        try:
            out = subprocess.check_output(
                'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA',
                shell=True, text=True, errors="ignore")
            if "0x1" in out:
                add("OK", "UAC", "UAC включён")
                log("ok", "UAC включён")
            else:
                add("CRIT", "UAC", "UAC выключен", "uac")
                log("crit", "UAC ВЫКЛЮЧЕН!")
        except Exception:
            pass

        try:
            out = subprocess.check_output(
                'powershell -Command "(Get-SmbServerConfiguration).EnableSMB1Protocol"',
                shell=True, text=True, errors="ignore", timeout=10)
            if "True" in out:
                add("CRIT", "SMB", "SMBv1 включён", "smbv1")
                log("crit", "SMBv1 активен — уязвимо!")
            else:
                add("OK", "SMB", "SMBv1 отключён")
                log("ok", "SMBv1 отключён")
        except Exception:
            pass

def check_services(log):
    log("info", "Проверка служб...")
    danger = ["telnet", "ftp", "rsh", "rlogin", "tftp"]
    found = False
    try:
        for p in psutil.process_iter(["name"]):
            n = (p.info["name"] or "").lower()
            for d in danger:
                if d in n:
                    add("WARN", "Services", f"Служба: {n}", "manual")
                    log("warn", f"Опасная служба: {n}")
                    found = True
    except Exception:
        pass
    if not found:
        log("ok", "Опасных служб нет")

def run_all(log):
    REPORT["findings"].clear()
    REPORT["score"] = 100
    REPORT["timestamp"] = datetime.datetime.now().isoformat()
    for fn in (check_os, check_users, check_net, check_protection, check_services):
        fn(log)

# ==================== GUI ====================
class App:
    def __init__(self, root):
        self.root = root
        root.title("Security Analyzer")
        root.geometry("1000x720")
        root.configure(bg=BG)
        self.log_box = None
        self._build()
        root.after(300, self.scan)

    def _build(self):
        top = tk.Frame(self.root, bg=BG)
        top.pack(fill="x", padx=20, pady=15)

        tk.Label(top, text="SECURITY ANALYZER", bg=BG, fg=FG,
                 font=("Segoe UI", 18, "bold")).pack(side="left")

        badge = "[ADMIN]" if IS_ADMIN else "[без прав админа]"
        bcolor = GREEN if IS_ADMIN else YELLOW
        tk.Label(top, text=badge, bg=BG, fg=bcolor,
                 font=("Segoe UI", 9, "bold")).pack(side="left", padx=10)

        self.btn_scan = tk.Button(top, text="Сканировать", command=self.scan,
                                  bg=ACCENT, fg="white", relief="flat",
                                  font=("Segoe UI", 10, "bold"),
                                  padx=14, pady=6, cursor="hand2")
        self.btn_scan.pack(side="right")

        tk.Button(top, text="Экспорт", command=self.export,
                  bg=ACCENT2, fg="white", relief="flat",
                  font=("Segoe UI", 10, "bold"),
                  padx=14, pady=6, cursor="hand2").pack(side="right", padx=6)

        self.status = tk.Label(self.root, text="Готов к работе",
                                bg=BG, fg=FG2, font=("Segoe UI", 9), anchor="w")
        self.status.pack(fill="x", padx=20)

        # лог
        wrap = tk.Frame(self.root, bg=CARD)
        wrap.pack(fill="both", expand=True, padx=20, pady=15)
        sb = tk.Scrollbar(wrap, bd=0)
        sb.pack(side="right", fill="y")
        self.log_box = tk.Text(wrap, bg=CARD, fg=FG, insertbackground=FG,
                                font=("Consolas", 10), relief="flat", bd=0,
                                padx=14, pady=12, wrap="word",
                                yscrollcommand=sb.set)
        self.log_box.pack(fill="both", expand=True)
        sb.config(command=self.log_box.yview)
        self.log_box.tag_config("ok", foreground=GREEN)
        self.log_box.tag_config("warn", foreground=YELLOW)
        self.log_box.tag_config("crit", foreground=RED)
        self.log_box.tag_config("info", foreground=FG2)

    def _log(self, level, msg):
        prefix = {"ok": "  [+] ", "warn": "  [!] ", "crit": "  [x] ",
                  "info": "  [i] "}.get(level, "      ")
        self.root.after(0, lambda: self._insert(prefix + msg + "\n", level))

    def _insert(self, text, level):
        self.log_box.insert("end", text, level)
        self.log_box.see("end")

    def scan(self):
        self.btn_scan.config(state="disabled", text="Сканирую...")
        self.log_box.delete("1.0", "end")
        self.status.config(text="Сканирование...")

        def work():
            try:
                run_all(self._log)
            except Exception as e:
                self._log("crit", f"Ошибка: {e}")
            self.root.after(0, self._done)

        threading.Thread(target=work, daemon=True).start()

    def _done(self):
        self.btn_scan.config(state="normal", text="Сканировать")
        s = REPORT["score"]
        self.status.config(text=f"Готово. Оценка: {s}/100")
        try:
            with open("security_report.json", "w", encoding="utf-8") as f:
                json.dump(REPORT, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
        self._popup()

    # ---------- окно с чекбоксами ----------
    def _popup(self):
        win = tk.Toplevel(self.root)
        win.title("Проблемы и исправления")
        win.configure(bg=BG)
        win.transient(self.root)
        win.grab_set()
        win.geometry("820x640")

        score = REPORT["score"]
        if score >= 90:
            col, txt = GREEN, "ОТЛИЧНО"
        elif score >= 70:
            col, txt = "#a4d038", "УДОВЛЕТВОРИТЕЛЬНО"
        elif score >= 50:
            col, txt = YELLOW, "ТРЕБУЕТ ВНИМАНИЯ"
        else:
            col, txt = RED, "КРИТИЧНО"

        head = tk.Frame(win, bg=CARD2, height=80)
        head.pack(fill="x")
        head.pack_propagate(False)
        tk.Label(head, text="РЕЗУЛЬТАТЫ АНАЛИЗА", bg=CARD2, fg=FG,
                 font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=20, pady=(14, 0))
        tk.Label(head, text=f"Оценка: {score}/100 — {txt}",
                 bg=CARD2, fg=col,
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=20)

        problems = [f for f in REPORT["findings"] if f["level"] in ("CRIT", "WARN")]

        tk.Label(win, text="Отметьте галочками проблемы, которые хотите исправить:",
                 bg=BG, fg=FG, font=("Segoe UI", 10)).pack(anchor="w", padx=20, pady=(10, 4))

        # Область со скроллом
        body = tk.Frame(win, bg=CARD)
        body.pack(fill="both", expand=True, padx=20, pady=6)

        canvas = tk.Canvas(body, bg=CARD, highlightthickness=0)
        scroll = tk.Scrollbar(body, orient="vertical", command=canvas.yview, bd=0)
        inner = tk.Frame(canvas, bg=CARD)

        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)

        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        # мышь-колесо
        def _wheel(e):
            canvas.yview_scroll(int(-1*(e.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _wheel)

        self.vars = []   # (var, fix_id, message)

        if not problems:
            tk.Label(inner, text="Проблем не обнаружено — всё чисто!",
                     bg=CARD, fg=GREEN,
                     font=("Segoe UI", 11, "bold")).pack(padx=20, pady=30)
        else:
            for i, f in enumerate(problems):
                row = tk.Frame(inner, bg=CARD if i % 2 == 0 else CARD2)
                row.pack(fill="x", padx=2, pady=1)

                var = tk.BooleanVar(value=(f["level"] == "CRIT"))
                self.vars.append((var, f.get("fix_id", "manual"), f["message"]))

                mark_col = RED if f["level"] == "CRIT" else YELLOW
                tk.Label(row, text="●", bg=row["bg"], fg=mark_col,
                         font=("Segoe UI", 12)).pack(side="left", padx=(10, 4), pady=6)

                cb = tk.Checkbutton(row, variable=var,
                                    bg=row["bg"], activebackground=row["bg"],
                                    selectcolor=BG, bd=0, highlightthickness=0)
                cb.pack(side="left")

                tk.Label(row, text=f["message"], bg=row["bg"], fg=FG,
                         font=("Segoe UI", 10), anchor="w",
                         justify="left", wraplength=560).pack(side="left", pady=6)

                fix_id = f.get("fix_id", "manual")
                fname = FIXES.get(fix_id, ("—", None))[0]
                tk.Label(row, text=f"→ {fname}", bg=row["bg"], fg=FG2,
                         font=("Segoe UI", 8, "italic")).pack(side="right", padx=10)

        # Кнопки
        btns = tk.Frame(win, bg=BG)
        btns.pack(fill="x", padx=20, pady=(4, 16))

        tk.Button(btns, text="Выбрать всё",
                  command=lambda: [v.set(True) for v, _, _ in self.vars],
                  bg=CARD2, fg=FG, relief="flat",
                  font=("Segoe UI", 10), padx=12, pady=8,
                  cursor="hand2").pack(side="left")

        tk.Button(btns, text="Снять всё",
                  command=lambda: [v.set(False) for v, _, _ in self.vars],
                  bg=CARD2, fg=FG, relief="flat",
                  font=("Segoe UI", 10), padx=12, pady=8,
                  cursor="hand2").pack(side="left", padx=6)

        tk.Button(btns, text="Закрыть", command=win.destroy,
                  bg=CARD2, fg=FG, relief="flat",
                  font=("Segoe UI", 10), padx=12, pady=8,
                  cursor="hand2").pack(side="right")

        tk.Button(btns, text="Исправить выбранное",
                  command=lambda: self._apply(win),
                  bg=GREEN, fg="white", relief="flat",
                  font=("Segoe UI", 11, "bold"), padx=18, pady=8,
                  cursor="hand2").pack(side="right", padx=6)

        win.bind("<Escape>", lambda e: win.destroy())

    # ---------- применение фиксов ----------
    def _apply(self, win):
        chosen = [(fid, msg) for v, fid, msg in self.vars if v.get()]
        if not chosen:
            messagebox.showinfo("Пусто", "Ничего не выбрано.")
            return

        if not IS_ADMIN:
            if not messagebox.askyesno(
                "Нет прав администратора",
                "Программа запущена БЕЗ прав администратора.\n"
                "Большинство исправлений не сработает.\n\n"
                "Продолжить всё равно?"):
                return

        results = []
        for fix_id, msg in chosen:
            title, func = FIXES.get(fix_id, ("—", None))
            if func is None:
                results.append(("SKIP", msg, "нет функции"))
                continue
            try:
                info = func()
                results.append(("OK", msg, info))
            except Exception as e:
                results.append(("FAIL", msg, str(e)))

        win.destroy()

        # Окно с результатами
        res = tk.Toplevel(self.root)
        res.title("Результаты исправлений")
        res.configure(bg=BG)
        res.geometry("640x460")
        res.transient(self.root)

        tk.Label(res, text="ИТОГИ ИСПРАВЛЕНИЙ", bg=BG, fg=FG,
                 font=("Segoe UI", 13, "bold")).pack(pady=12)

        box = tk.Text(res, bg=CARD, fg=FG, font=("Consolas", 10),
                      relief="flat", bd=0, padx=14, pady=12, wrap="word")
        box.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        box.tag_config("ok", foreground=GREEN)
        box.tag_config("fail", foreground=RED)
        box.tag_config("skip", foreground=YELLOW)

        for status, msg, info in results:
            if status == "OK":
                box.insert("end", f"  [OK] {msg}\n        {info}\n\n", "ok")
            elif status == "FAIL":
                box.insert("end", f"  [X] {msg}\n      {info}\n\n", "fail")
            else:
                box.insert("end", f"  [-] {msg} ({info})\n\n", "skip")

        tk.Button(res, text="Закрыть", command=res.destroy,
                  bg=ACCENT, fg="white", relief="flat",
                  font=("Segoe UI", 10, "bold"), padx=20, pady=8,
                  cursor="hand2").pack(pady=(0, 14))

        # Пересканируем
        self.root.after(300, self.scan)

    def export(self):
        if not REPORT["findings"]:
            messagebox.showinfo("Экспорт", "Сначала сделайте скан.")
            return
        fn = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile=f"report_{datetime.datetime.now():%Y%m%d_%H%M%S}.json",
            filetypes=[("JSON", "*.json"), ("Все", "*.*")])
        if not fn:
            return
        try:
            with open(fn, "w", encoding="utf-8") as f:
                json.dump(REPORT, f, ensure_ascii=False, indent=2)
            messagebox.showinfo("Экспорт", f"Сохранено:\n{fn}")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))


# ==================== ЗАПУСК ====================
def main():
    root = tk.Tk()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()