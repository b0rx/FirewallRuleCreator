# FirewallRuleCreator

**FirewallRuleCreator** is a simple and fast Windows tool that allows you to quickly add or remove firewall rules for multiple applications without manually navigating through advanced Windows firewall settings.

## Features
- Block or allow connections for any `.exe` file  
- Supports **inbound**, **outbound**, or **both** directions  
- Choose profiles: **Domain, Private, Public**  
- **Folder scanning** in the background to find all `.exe` files (UI doesn't freeze)  
- **Multiple selection** of `.exe` files for batch processing  
- **Batch removal**: Select multiple rows in the list to remove them all at once  
- **Direct editing** of rule names directly in the table  
- **Auto-renaming** of duplicate `.exe` files with `_2`, `_3`, etc. (highlighted in yellow)  
- **Completely new modern Dark UI** using `PySide6`  
- Auto-requests Administrator privileges on startup  
- No installation required – just run the `.exe`  

## Download & Installation
1. **Download** `FirewallRuleCreator.exe` from the [Releases](https://github.com/b0rx/FirewallRuleCreator/releases) page.  
2. Run the `.exe` – **No installation required!**  

## How to Use
1. Open the program (it will automatically ask for admin rights).  
2. Click **"Select Multiple EXEs"** or **"Select Folder"** to add files to your list.  
3. Select the files you want to process, or use **"Remove Selected"** to clean up the list.  
4. Choose your **Rule Settings** on the right panel (Action, Direction, Profiles).  
5. Click **"Create Rules"** – Done!

## Building from Source
If you want to modify or compile the program yourself, follow these steps:

### Install Dependencies:
```bash
pip install PySide6
```
