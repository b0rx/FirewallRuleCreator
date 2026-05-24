# © 2026 B0rx. All rights reserved.
# Version: v0.4 Beta / 24.05.2026

import os
import sys
import ctypes
import traceback
import subprocess
from pathlib import Path
from typing import Dict, List
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QPalette, QColor, QFont
from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QLabel, QFileDialog, QTableWidget, QTableWidgetItem,
        QCheckBox, QRadioButton, QGroupBox, QProgressBar, QMessageBox,
        QHeaderView, QLineEdit, QStyleFactory, QAbstractItemView)

os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
os.environ["QT_ENABLE_HIGHDPI_SCALING"] = "1"

CREATE_NO_WINDOW = 0x08000000

class FolderScannerThread(QThread):
    finished_signal = Signal(list)

    def __init__(self, folder_path: str):
        super().__init__()
        self.folder_path = folder_path

    def run(self):
        folder = Path(self.folder_path)
        exe_files = [str(p) for p in folder.rglob("*.exe")]
        self.finished_signal.emit(exe_files)

class RuleCreatorThread(QThread):
    progress_signal = Signal(int, int)
    log_signal = Signal(str)
    finished_signal = Signal(int, int)

    def __init__(self, tasks: List[dict], overwrite: bool):
        super().__init__()
        self.tasks = tasks
        self.overwrite = overwrite
        self.ADD_CMD = 'netsh advfirewall firewall add rule'
        self.DELETE_CMD = 'netsh advfirewall firewall delete rule'

    def run(self):
        total = len(self.tasks)
        success_count = 0

        for i, task in enumerate(self.tasks):
            name = task["name"]
            program = task["program"]
            action = task["action"]
            directions = task["directions"]
            profiles = task["profiles"]

            try:
                for dir_ in directions:
                    if self.overwrite:
                        del_cmd = f'{self.DELETE_CMD} name="{name}" dir={dir_}'
                        subprocess.run(del_cmd, shell=True, creationflags=CREATE_NO_WINDOW,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                    cmd = f'{self.ADD_CMD} name="{name}" dir={dir_} action={action} program="{program}" profile={profiles}'
                    subprocess.run(cmd, shell=True, check=True, creationflags=CREATE_NO_WINDOW,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                success_count += 1
            except Exception as e:
                self.log_signal.emit(f"Error processing {name}: {str(e)}")

            self.progress_signal.emit(i + 1, total)

        self.finished_signal.emit(success_count, total)

class FirewallRuleCreator(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firewall Rule Creator")
        self.resize(1100, 700) 
        self.exe_data: Dict[str, dict] = {}
        
        self.setup_ui()
        self.apply_dark_theme()

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(15)

        title_label = QLabel("Firewall Rule Creator")
        title_label.setFont(QFont("Segoe UI", 22, QFont.Bold))
        left_layout.addWidget(title_label)

        btn_layout = QHBoxLayout()
        self.btn_add_files = QPushButton("Select Multiple EXEs")
        self.btn_add_folder = QPushButton("Select Folder")
        self.btn_remove_selected = QPushButton("Remove Selected")
        self.btn_clear = QPushButton("Clear List")

        self.btn_add_files.clicked.connect(self.browse_multiple_exes)
        self.btn_add_folder.clicked.connect(self.browse_folder)
        self.btn_remove_selected.clicked.connect(self.remove_selected_exes)
        self.btn_clear.clicked.connect(self.clear_list)

        for btn in [self.btn_add_files, self.btn_add_folder, self.btn_remove_selected, self.btn_clear]:
            btn.setMinimumHeight(35)
            btn_layout.addWidget(btn)
        
        left_layout.addLayout(btn_layout)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Select", "Rule Name", "File Path", "Action"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Fixed)
        self.table.setColumnWidth(0, 60)
        self.table.setColumnWidth(1, 220)
        self.table.setColumnWidth(3, 80)
        self.table.setTextElideMode(Qt.ElideMiddle)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)

        left_layout.addWidget(self.table)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        left_layout.addWidget(self.progress_bar)

        right_panel = QWidget()
        right_panel.setFixedWidth(280)
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(15)
        settings_label = QLabel("Rule Settings")
        settings_label.setFont(QFont("Segoe UI", 14, QFont.Bold))
        right_layout.addWidget(settings_label)

        action_groupbox = QGroupBox("Action")
        action_layout = QVBoxLayout()
        self.rb_block = QRadioButton("Block Connection")
        self.rb_allow = QRadioButton("Allow Connection")
        self.rb_block.setChecked(True)
        action_layout.addWidget(self.rb_block)
        action_layout.addWidget(self.rb_allow)
        action_groupbox.setLayout(action_layout)
        right_layout.addWidget(action_groupbox)

        dir_groupbox = QGroupBox("Direction")
        dir_layout = QVBoxLayout()
        self.rb_in = QRadioButton("Inbound")
        self.rb_out = QRadioButton("Outbound")
        self.rb_both = QRadioButton("Both (Inbound + Outbound)")
        self.rb_both.setChecked(True)
        dir_layout.addWidget(self.rb_in)
        dir_layout.addWidget(self.rb_out)
        dir_layout.addWidget(self.rb_both)
        dir_groupbox.setLayout(dir_layout)
        right_layout.addWidget(dir_groupbox)

        prof_groupbox = QGroupBox("Network Profiles")
        prof_layout = QVBoxLayout()
        self.cb_domain = QCheckBox("Domain")
        self.cb_private = QCheckBox("Private")
        self.cb_public = QCheckBox("Public")
        self.cb_domain.setChecked(True)
        self.cb_private.setChecked(True)
        self.cb_public.setChecked(True)
        prof_layout.addWidget(self.cb_domain)
        prof_layout.addWidget(self.cb_private)
        prof_layout.addWidget(self.cb_public)
        prof_groupbox.setLayout(prof_layout)
        right_layout.addWidget(prof_groupbox)

        opt_groupbox = QGroupBox("Advanced Options")
        opt_layout = QVBoxLayout()
        self.cb_overwrite = QCheckBox("Overwrite existing rules")
        self.cb_overwrite.setChecked(True)
        opt_layout.addWidget(self.cb_overwrite)
        opt_groupbox.setLayout(opt_layout)
        right_layout.addWidget(opt_groupbox)
        right_layout.addStretch()

        self.btn_create = QPushButton("Create Rules")
        self.btn_create.setMinimumHeight(55)
        self.btn_create.setFont(QFont("Segoe UI", 12, QFont.Bold))
        self.btn_create.setStyleSheet("""
            QPushButton {
                background-color: #52555e; 
                color: white; 
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #6a6e7a;
            }
            QPushButton:pressed {
                background-color: #3c3e45;
            }
            QPushButton:disabled {
                background-color: #3b3b3b;
                color: #888888;
            }
        """)
        self.btn_create.clicked.connect(self.create_rules)
        right_layout.addWidget(self.btn_create)

        main_layout.addWidget(left_panel, 1)
        main_layout.addWidget(right_panel, 0)

    def apply_dark_theme(self):
        QApplication.setStyle(QStyleFactory.create("Fusion"))
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(32, 32, 32))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(38, 38, 38))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(50, 50, 50))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Highlight, QColor(0, 120, 215))
        dark_palette.setColor(QPalette.HighlightedText, Qt.white)
        QApplication.setPalette(dark_palette)
        self.setStyleSheet("""
            QTableWidget { gridline-color: #3f3f3f; border: 1px solid #3f3f3f; border-radius: 4px; }
            QGroupBox { border: 1px solid #4f4f4f; border-radius: 5px; margin-top: 1ex; font-weight: bold; }
            QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 3px; color: #aaaaaa; }
        """)

    def browse_multiple_exes(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select EXEs", "", "Executable files (*.exe);;All files (*.*)")
        if files:
            self.update_exe_list(files)

    def browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if not folder:
            return
        
        self.btn_add_folder.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)

        self.scanner_thread = FolderScannerThread(folder)
        self.scanner_thread.finished_signal.connect(self.on_scan_complete)
        self.scanner_thread.start()

    def on_scan_complete(self, exe_files):
        self.progress_bar.setVisible(False)
        self.btn_add_folder.setEnabled(True)
        if exe_files:
            self.update_exe_list(exe_files)
        else:
            QMessageBox.information(self, "Information", "No EXE files found in the selected folder!")

    def update_exe_list(self, new_exes):
        existing_names = {data["rule_name"] for data in self.exe_data.values()}
        
        for path in new_exes:
            path = str(Path(path).resolve())
            if path not in self.exe_data:
                base_name = Path(path).stem
                rule_name = base_name
                counter = 2
                
                while rule_name in existing_names:
                    rule_name = f"{base_name}_{counter}"
                    counter += 1
                
                self.exe_data[path] = {"selected": True, "rule_name": rule_name, "modified": counter > 2}
                existing_names.add(rule_name)
        
        self.refresh_table()

    def refresh_table(self):
        self.table.setRowCount(0)
        for path, data in self.exe_data.items():
            row = self.table.rowCount()
            self.table.insertRow(row)

            chk_widget = QWidget()
            chk_layout = QHBoxLayout(chk_widget)
            chk_layout.setContentsMargins(0,0,0,0)
            chk_layout.setAlignment(Qt.AlignCenter)
            chk = QCheckBox()
            chk.setChecked(data["selected"])
            chk.stateChanged.connect(lambda state, p=path: self.toggle_selection(p, state))
            chk_layout.addWidget(chk)
            self.table.setCellWidget(row, 0, chk_widget)

            name_input = QLineEdit(data["rule_name"])
            if data["modified"]:
                name_input.setStyleSheet("color: #FFD700; background-color: transparent; border: none;")
            else:
                name_input.setStyleSheet("background-color: transparent; border: none; color: white;")
            name_input.textChanged.connect(lambda text, p=path: self.update_rule_name(p, text))
            self.table.setCellWidget(row, 1, name_input)

            path_item = QTableWidgetItem(path)
            path_item.setFlags(path_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 2, path_item)

            del_btn = QPushButton("Remove")
            del_btn.setStyleSheet("QPushButton { background-color: #a63f3f; color: white; border-radius: 3px; margin: 2px; } QPushButton:hover { background-color: #a86363; }")
            del_btn.clicked.connect(lambda checked, p=path: self.delete_exe(p))
            self.table.setCellWidget(row, 3, del_btn)

    def toggle_selection(self, path, state):
        self.exe_data[path]["selected"] = (state == Qt.Checked.value)

    def update_rule_name(self, path, new_name):
        self.exe_data[path]["rule_name"] = new_name

    def delete_exe(self, path):
        if path in self.exe_data:
            del self.exe_data[path]
            self.refresh_table()

    def remove_selected_exes(self):
        selected_rows = set(item.row() for item in self.table.selectedItems())
        
        if not selected_rows:
            return

        paths_to_delete = []
        for row in selected_rows:
            path_item = self.table.item(row, 2)
            if path_item:
                paths_to_delete.append(path_item.text())

        for path in paths_to_delete:
            if path in self.exe_data:
                del self.exe_data[path]
        self.refresh_table()

    def clear_list(self):
        self.exe_data.clear()
        self.refresh_table()

    def create_rules(self):
        if not self.exe_data:
            QMessageBox.critical(self, "Error", "Please select at least one EXE file!")
            return

        selected_exes = {p: d for p, d in self.exe_data.items() if d["selected"]}
        if not selected_exes:
            QMessageBox.critical(self, "Error", "No EXEs checked for processing!")
            return

        profiles_list = []
        if self.cb_domain.isChecked(): profiles_list.append("domain")
        if self.cb_private.isChecked(): profiles_list.append("private")
        if self.cb_public.isChecked(): profiles_list.append("public")

        if not profiles_list:
            QMessageBox.critical(self, "Error", "Please select at least one network profile (Domain/Private/Public)!")
            return

        profiles_str = ",".join(profiles_list)
        action_val = "block" if self.rb_block.isChecked() else "allow"
        
        directions = []
        if self.rb_in.isChecked() or self.rb_both.isChecked(): directions.append("in")
        if self.rb_out.isChecked() or self.rb_both.isChecked(): directions.append("out")

        tasks = []
        for path, data in selected_exes.items():
            name = data["rule_name"].strip()
            if not name:
                continue
            tasks.append({
                "name": name,
                "program": str(Path(path)).replace("/", "\\"),
                "action": action_val,
                "directions": directions,
                "profiles": profiles_str
            })

        self.btn_create.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, len(tasks))
        self.progress_bar.setValue(0)

        overwrite = self.cb_overwrite.isChecked()
        self.creator_thread = RuleCreatorThread(tasks, overwrite)
        self.creator_thread.progress_signal.connect(self.update_progress)
        self.creator_thread.log_signal.connect(self.log_error)
        self.creator_thread.finished_signal.connect(self.on_creation_finished)
        self.creator_thread.start()

    def update_progress(self, current, total):
        self.progress_bar.setValue(current)

    def log_error(self, message):
        print(message) 

    def on_creation_finished(self, success_count, total):
        self.progress_bar.setVisible(False)
        self.btn_create.setEnabled(True)
        QMessageBox.information(self, "Success", f"Successfully created {success_count} / {total} firewall rules!")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def restart_as_admin():
    if is_admin():
        return True
    
    try:
        script = os.path.abspath(sys.argv[0])
        params = ' '.join([f'"{script}"'] + sys.argv[1:])
        
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        if ret <= 32:
            raise Exception(f"ShellExecute failed with return code {ret}")
    except Exception as e:
        ctypes.windll.user32.MessageBoxW(0, f"Could not request administrator privileges.\n{e}", "Error", 0x10)
        return False
    sys.exit(0)

def main():
    try:
        if not restart_as_admin():
            return
        app = QApplication(sys.argv)
        app.setFont(QFont("Segoe UI", 10))
        window = FirewallRuleCreator()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        error_msg = traceback.format_exc()
        ctypes.windll.user32.MessageBoxW(0, f"Application crashed:\n{error_msg}", "Critical Error", 0x10)

if __name__ == "__main__":
    main()
