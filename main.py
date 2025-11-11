# © 2025 B0rx. All rights reserved.
# Version: v0.2 Beta / 03.04.2025 /

import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import subprocess

class FirewallRuleCreator:
    def __init__(self, root):
        self.root = root
        self.root.title("Firewall Rule Creator")
        self.root.geometry("700x850")
        self.root.resizable(False, False)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.exe_data = {}
        self.direction = ctk.StringVar(value="both")
        self.action = ctk.StringVar(value="block")
        self.domain = ctk.BooleanVar(value=True)
        self.private = ctk.BooleanVar(value=True)
        self.public = ctk.BooleanVar(value=True)
        self.progress = None
        self.create_widgets()

    def create_widgets(self):
        main_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        main_frame.pack(pady=20, padx=20, fill="both", expand=True)

        title_label = ctk.CTkLabel(
            main_frame,
            text="Firewall Rule Creator",
            font=ctk.CTkFont(family="Arial", size=24, weight="bold"))
        title_label.pack(pady=(0, 20))

        selection_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        selection_frame.pack(fill="x", pady=10)
        
        ctk.CTkButton(selection_frame, text="Select Multiple EXEs", 
                     command=self.browse_multiple_exes, width=150).pack(side="left", padx=5)
        ctk.CTkButton(selection_frame, text="Select Folder", 
                     command=self.browse_folder, width=150).pack(side="left", padx=5)
        ctk.CTkButton(selection_frame, text="Clear List", 
                     command=self.clear_list, width=150).pack(side="left", padx=5)

        self.exe_frame = ctk.CTkScrollableFrame(main_frame, height=300)
        self.exe_frame.pack(fill="x", pady=10)

        settings_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        settings_frame.pack(fill="x", pady=10)

        action_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
        action_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(action_frame, text="Action:").pack(anchor="w")
        ctk.CTkRadioButton(action_frame, text="Block", value="block", 
                         variable=self.action).pack(anchor="w", pady=5)
        ctk.CTkRadioButton(action_frame, text="Allow", value="allow", 
                         variable=self.action).pack(anchor="w", pady=5)

        combined_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
        combined_frame.pack(fill="x", pady=10)

        direction_frame = ctk.CTkFrame(combined_frame, fg_color="transparent")
        direction_frame.pack(side="left", fill="y", padx=(0, 20))
        ctk.CTkLabel(direction_frame, text="Direction:").pack(anchor="w")
        ctk.CTkRadioButton(direction_frame, text="Inbound", value="in", 
                         variable=self.direction).pack(anchor="w", pady=5)
        ctk.CTkRadioButton(direction_frame, text="Outbound", value="out", 
                         variable=self.direction).pack(anchor="w", pady=5)
        ctk.CTkRadioButton(direction_frame, text="Both", value="both", 
                         variable=self.direction).pack(anchor="w", pady=5)

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
            main_frame,
            text="Create Rules",
            command=self.create_rules,
            fg_color="#2b2b2b",
            hover_color="#424242",
            border_color="#1f538d",
            border_width=2,
            font=ctk.CTkFont(family="Arial", size=14, weight="bold"),
            height=40).pack(pady=15)

    def browse_multiple_exes(self):
        files = filedialog.askopenfilenames(
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")])
        if files:
            self.update_exe_list(list(files))

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            exe_files = []
            for root, _, files in os.walk(folder):
                for file in files:
                    if file.lower().endswith('.exe'):
                        exe_files.append(os.path.join(root, file))
            if exe_files:
                self.update_exe_list(exe_files)
            else:
                messagebox.showinfo("Info", "No EXE files found in the selected folder!")

    def update_exe_list(self, new_exes):
        for path in new_exes:
            if path not in self.exe_data:
                base_name = os.path.splitext(os.path.basename(path))[0]
                rule_name = base_name
                existing_names = [data["rule_name"].get() for data in self.exe_data.values()]
                counter = 2
                is_modified = False
                while rule_name in existing_names:
                    rule_name = f"{base_name}_{counter}"
                    is_modified = True
                    counter += 1
                self.exe_data[path] = {
                    "selected": ctk.BooleanVar(value=True),
                    "rule_name": ctk.StringVar(value=rule_name),
                    "modified": is_modified
                }
        self.refresh_exe_list()

    def refresh_exe_list(self):
        for widget in self.exe_frame.winfo_children():
            widget.destroy()
        
        for path, data in self.exe_data.items():
            frame = ctk.CTkFrame(self.exe_frame)
            frame.pack(fill="x", pady=5)
            
            top_frame = ctk.CTkFrame(frame, fg_color="transparent")
            top_frame.pack(fill="x")
            
            ctk.CTkCheckBox(top_frame, text=os.path.basename(path), 
                          variable=data["selected"]).pack(side="left", padx=5)
            
            entry = ctk.CTkEntry(top_frame, textvariable=data["rule_name"], width=200,
                               border_width=2,
                               border_color="#FFFF00" if data["modified"] else "#565B5E")
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

    def check_rule_exists(self, name, direction):
        try:
            cmd = f'netsh advfirewall firewall show rule name="{name}" dir={direction}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return "No rules match the specified criteria" not in result.stdout
        except subprocess.CalledProcessError:
            return False

    def create_rules(self):
        if not self.exe_data:
            messagebox.showerror("Error", "Please select at least one EXE file!", parent=self.root)
            return
        if not (self.domain.get() or self.private.get() or self.public.get()):
            messagebox.showerror("Error", "Please select at least one profile!", parent=self.root)
            return

        selected_exes = {path: data for path, data in self.exe_data.items() if data["selected"].get()}
        if not selected_exes:
            messagebox.showerror("Error", "Please select at least one EXE to create rules for!", parent=self.root)
            return

        try:
            direction = self.direction.get()
            action = self.action.get()
            base_cmd = 'netsh advfirewall firewall add rule'
            delete_cmd = 'netsh advfirewall firewall delete rule'

            profiles = []
            if self.domain.get(): profiles.append("domain")
            if self.private.get(): profiles.append("private")
            if self.public.get(): profiles.append("public")
            profiles_str = ",".join(profiles)

            directions = ["in", "out"] if direction == "both" else [direction]
            total_rules = len(selected_exes) * len(directions)
            current_rule = 0

            self.progress.pack(fill="x", pady=10)
            self.root.update()

            for program, data in selected_exes.items():
                name = data["rule_name"].get()
                if not name:
                    messagebox.showwarning("Warning", f"Skipping {program} - No rule name specified!")
                    continue
                    
                if not os.path.exists(program):
                    messagebox.showwarning("Warning", f"Skipping {program} - File does not exist!")
                    continue
                
                program = program.replace("/", "\\")
                
                rule_exists = any(self.check_rule_exists(name, dir) for dir in directions)
                
                if rule_exists:
                    response = messagebox.askyesno(
                        "Rule Exists",
                        f"A rule with the name '{name}' already exists. Overwrite?",
                        parent=self.root)
                    if not response:
                        continue
                    for dir in directions:
                        subprocess.run(f'{delete_cmd} name="{name}" dir={dir}', 
                                     shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                for dir in directions:
                    cmd = f'{base_cmd} name="{name}" dir={dir} action={action} program="{program}" profile={profiles_str}'
                    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    current_rule += 1
                    self.progress.set(current_rule / total_rules)
                    self.root.update()

            self.progress.pack_forget()
            messagebox.showinfo("Success", "Firewall rules successfully created!", parent=self.root)

        except subprocess.CalledProcessError as e:
            self.progress.pack_forget()
            messagebox.showerror("Error", f"Error creating rules: {str(e)}", parent=self.root)
        except Exception as e:
            self.progress.pack_forget()
            messagebox.showerror("Error", f"Unknown error: {str(e)}", parent=self.root)

def main():
    root = ctk.CTk()
    app = FirewallRuleCreator(root)
    root.mainloop()

if __name__ == "__main__":
    main()

