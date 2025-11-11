# © 2025 B0rx. All rights reserved.
# Version: v0.3 Beta / 11.11.2025

import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import subprocess
import threading
import ctypes
import sys
from pathlib import Path
from typing import Dict, Set

class FirewallRuleCreator:
    def __init__(self, root):
        self.root = root
        self.root.title("Firewall Rule Creator")
        self.root.geometry("700x850")
        self.root.resizable(False, False)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        
        self.exe_data: Dict[str, Dict] = {}
        self.direction = ctk.StringVar(value="both")
        self.action = ctk.StringVar(value="block")
        self.domain = ctk.BooleanVar(value=True)
        self.private = ctk.BooleanVar(value=True)
        self.public = ctk.BooleanVar(value=True)
        self.progress = None
        self.select_multiple_btn = None
        self.select_folder_btn = None
        self.clear_btn = None
        
        self.create_widgets()

    ADD_CMD = 'netsh advfirewall firewall add rule'
    DELETE_CMD = 'netsh advfirewall firewall delete rule'
    SHOW_ALL_CMD = 'netsh advfirewall firewall show rule name=all'
    NO_RULES_MSG = "No rules match the specified criteria"

    def create_widgets(self):
        main_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        main_frame.pack(pady=20, padx=20, fill="both", expand=True)

        title_label = ctk.CTkLabel(
            main_frame, text="Firewall Rule Creator",
            font=ctk.CTkFont(family="Arial", size=24, weight="bold")
        )
        title_label.pack(pady=(0, 20))

        selection_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        selection_frame.pack(fill="x", pady=10)

        self.select_multiple_btn = ctk.CTkButton(
            selection_frame, text="Select Multiple EXEs", command=self.browse_multiple_exes, width=150
        )
        self.select_multiple_btn.pack(side="left", padx=5)

        self.select_folder_btn = ctk.CTkButton(
            selection_frame, text="Select Folder", command=self.browse_folder, width=150
        )
        self.select_folder_btn.pack(side="left", padx=5)

        self.clear_btn = ctk.CTkButton(
            selection_frame, text="Clear List", command=self.clear_list, width=150
        )
        self.clear_btn.pack(side="left", padx=5)

        self.exe_frame = ctk.CTkScrollableFrame(main_frame, height=300)
        self.exe_frame.pack(fill="x", pady=10)

        settings_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        settings_frame.pack(fill="x", pady=10)

        action_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
        action_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(action_frame, text="Action:").pack(anchor="w")
        ctk.CTkRadioButton(action_frame, text="Block", value="block", variable=self.action).pack(anchor="w", pady=5)
        ctk.CTkRadioButton(action_frame, text="Allow", value="allow", variable=self.action).pack(anchor="w", pady=5)

        combined_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
        combined_frame.pack(fill="x", pady=10)

        direction_frame = ctk.CTkFrame(combined_frame, fg_color="transparent")
        direction_frame.pack(side="left", fill="y", padx=(0, 20))
        ctk.CTkLabel(direction_frame, text="Direction:").pack(anchor="w")
        ctk.CTkRadioButton(direction_frame, text="Inbound", value="in", variable=self.direction).pack(anchor="w", pady=5)
        ctk.CTkRadioButton(direction_frame, text="Outbound", value="out", variable=self.direction).pack(anchor="w", pady=5)
        ctk.CTkRadioButton(direction_frame, text="Both", value="both", variable=self.direction).pack(anchor="w", pady=5)

        profile_frame = ctk.CTkFrame(combined_frame, fg_color="transparent")
        profile_frame.pack(side="right", fill="y")
        ctk.CTkLabel(profile_frame, text="Profiles:").pack(anchor="w")
        ctk.CTkCheckBox(profile_frame, text="Domain", variable=self.domain).pack(anchor="w", pady=5)
        ctk.CTkCheckBox(profile_frame, text="Private", variable=self.private).pack(anchor="w", pady=5)
        ctk.CTkCheckBox(profile_frame, text="Public", variable=self.public).pack(anchor="w", pady=5)

        self.progress = ctk.CTkProgressBar(main_frame)
        self.progress.pack(fill="x", pady=10)
        self.progress.set(0)
        self.progress.pack_forget()

        ctk.CTkButton(
            main_frame, text="Create Rules", command=self.create_rules,
            fg_color="#2b2b2b", hover_color="#424242", border_color="#1f538d",
            border_width=2, font=ctk.CTkFont(family="Arial", size=14, weight="bold"), height=40
        ).pack(pady=15)

    def browse_multiple_exes(self):
        files = filedialog.askopenfilenames(filetypes=[("Executable files", "*.exe"), ("All files", "*.*")])
        if files:
            self.update_exe_list(list(files))

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
        self.select_folder_btn.configure(state="disabled")
        self.progress.pack(fill="x", pady=10)
        self.progress.set(0)

        def scan_folder():
            folder_path = Path(folder)
            exe_files = [str(p) for p in folder_path.rglob("*.exe")]
            self.root.after(0, lambda: self.on_scan_complete(exe_files))

        thread = threading.Thread(target=scan_folder, daemon=True)
        thread.start()

    def on_scan_complete(self, exe_files):
        self.progress.pack_forget()
        self.select_folder_btn.configure(state="normal")
        if exe_files:
            self.update_exe_list(exe_files)
        else:
            messagebox.showinfo("Info", "No EXE files found in the selected folder!")

    def update_exe_list(self, new_exes):
        existing_names = {data["rule_name"].get() for data in self.exe_data.values()}
        for path in new_exes:
            path = str(Path(path))
            if path not in self.exe_data:
                base_name = Path(path).stem
                rule_name = base_name
                counter = 2
                while rule_name in existing_names:
                    rule_name = f"{base_name}_{counter}"
                    counter += 1
                self.exe_data[path] = {
                    "selected": ctk.BooleanVar(value=True),
                    "rule_name": ctk.StringVar(value=rule_name),
                    "modified": counter > 2 
                }
                existing_names.add(rule_name)
        self.refresh_exe_list()

    def refresh_exe_list(self):
        for widget in self.exe_frame.winfo_children():
            widget.destroy()

        for path, data in self.exe_data.items():
            frame = ctk.CTkFrame(self.exe_frame)
            frame.pack(fill="x", pady=5)

            top_frame = ctk.CTkFrame(frame, fg_color="transparent")
            top_frame.pack(fill="x")

            ctk.CTkCheckBox(top_frame, text=Path(path).name, variable=data["selected"]).pack(side="left", padx=5)

            border_color = "#FFFF00" if data["modified"] else "#565B5E"
            entry = ctk.CTkEntry(top_frame, textvariable=data["rule_name"], width=200,
                                 border_width=2, border_color=border_color)
            entry.pack(side="left", padx=5)

            ctk.CTkButton(top_frame, text="Delete", width=80,
                          command=lambda p=path: self.delete_exe(p)).pack(side="right", padx=5)

            ctk.CTkLabel(frame, text=path, font=("Arial", 8),
                         wraplength=650, justify="left").pack(anchor="w", padx=10)

    def delete_exe(self, path):
        if path in self.exe_data:
            del self.exe_data[path]
            self.refresh_exe_list()

    def clear_list(self):
        self.exe_data.clear()
        self.refresh_exe_list()

    def get_existing_rules(self) -> Dict[str, Set[str]]:
        """Fetch all existing rules once and parse dirs per name."""
        try:
            result = subprocess.run(self.SHOW_ALL_CMD, shell=True, capture_output=True, text=True, encoding='utf-8')
            if result.returncode != 0 or self.NO_RULES_MSG in result.stdout:
                return {}

            existing: Dict[str, Set[str]] = {}
            lines = result.stdout.splitlines()
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                if line.startswith("Rule Name:"):
                    name = line.split(":", 1)[1].strip().strip('"')
                    dirs = set()
                    i += 1
                    while i < len(lines) and not lines[i].strip().startswith("Rule Name:"):
                        dline = lines[i].strip()
                        if dline.startswith("Dir:"):
                            dir_val = dline.split(":", 1)[1].strip().lower()
                            dirs.add(dir_val)
                        i += 1
                    if name and dirs:
                        existing.setdefault(name, set()).update(dirs)
                else:
                    i += 1
            return existing
        except Exception:
            return {}

    def create_rules(self):
        if not self.exe_data:
            messagebox.showerror("Error", "Please select at least one EXE file!", parent=self.root)
            return
        if not (self.domain.get() or self.private.get() or self.public.get()):
            messagebox.showerror("Error", "Please select at least one profile!", parent=self.root)
            return

        selected_exes = {p: d for p, d in self.exe_data.items() if d["selected"].get()}
        if not selected_exes:
            messagebox.showerror("Error", "Please select at least one EXE to create rules for!", parent=self.root)
            return

        profiles = [p for p, var in [("domain", self.domain), ("private", self.private), ("public", self.public)] if var.get()]
        if not profiles:
            return
        profiles_str = ",".join(profiles)
        directions = ["in", "out"] if self.direction.get() == "both" else [self.direction.get()]

        existing_rules = self.get_existing_rules()

        total_rules = len(selected_exes) * len(directions)
        current_rule = 0

        self.progress.pack(fill="x", pady=10)
        self.progress.set(0)
        self.root.update()

        try:
            for program, data in selected_exes.items():
                name = data["rule_name"].get().strip()
                if not name:
                    messagebox.showwarning("Warning", f"Skipping {program} - No rule name specified!")
                    continue

                program_path = Path(program)
                if not program_path.exists():
                    messagebox.showwarning("Warning", f"Skipping {program} - File does not exist!")
                    continue

                program_str = str(program_path).replace("/", "\\")

                rule_dirs = existing_rules.get(name, set())
                rule_exists = any(d in rule_dirs for d in directions)

                if rule_exists:
                    response = messagebox.askyesno("Rule Exists", f"A rule with the name '{name}' already exists. Overwrite?", parent=self.root)
                    if not response:
                        continue

                    for dir_ in directions:
                        if dir_ in rule_dirs:
                            subprocess.run(f'{self.DELETE_CMD} name="{name}" dir={dir_}', shell=True,
                                           check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                for dir_ in directions:
                    cmd = f'{self.ADD_CMD} name="{name}" dir={dir_} action={self.action.get()} program="{program_str}" profile={profiles_str}'
                    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    current_rule += 1
                    self.progress.set(current_rule / total_rules)
                    self.root.update()

            self.progress.pack_forget()
            messagebox.showinfo("Success", f"Successfully created {current_rule} firewall rules!", parent=self.root)

        except subprocess.CalledProcessError as e:
            self.progress.pack_forget()
            messagebox.showerror("Error", f"Error creating rules: {str(e)}", parent=self.root)
        except Exception as e:
            self.progress.pack_forget()
            messagebox.showerror("Error", f"Unknown error: {str(e)}", parent=self.root)


def is_admin():
    """Check if the current process has admin rights."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def restart_as_admin():
    """Restart the script with admin rights."""
    if is_admin():
        return True
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
    except Exception:
        messagebox.showerror("Error", "Failed to elevate privileges. Please run as Administrator manually.")
        return False
    sys.exit(0)

def main():
    if not restart_as_admin():
        return

    root = ctk.CTk()
    app = FirewallRuleCreator(root)
    root.mainloop()

if __name__ == "__main__":
    main()

