import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import threading

class WhisperingGuardian:
    def __init__(self, master):
        self.master = master
        master.title("The Whispering Guardian")
        master.geometry("800x600")

        self.setup_gui()
        self.suspicious_files = []
        self.scan_in_progress = False
        self.quarantine_dir = os.path.join(os.path.expanduser("~"), "Whispering_Guardian_Quarantine")

    def setup_gui(self):
        # Main frame
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Menu bar
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="View Quarantined Files", command=self.show_quarantined_files)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.master.quit)

        # Scan button
        self.scan_button = ttk.Button(main_frame, text="Select Directory to Scan", command=self.start_scan)
        self.scan_button.pack(pady=10)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=10)

        # Results area
        self.result_tree = ttk.Treeview(main_frame, columns=("Path", "Status"), show="headings")
        self.result_tree.heading("Path", text="File Path")
        self.result_tree.heading("Status", text="Status")
        self.result_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        # Quarantine button
        self.quarantine_button = ttk.Button(main_frame, text="Quarantine Selected", command=self.quarantine_selected)
        self.quarantine_button.pack(pady=10)

    def start_scan(self):
        if self.scan_in_progress:
            messagebox.showwarning("Scan in Progress", "A scan is already in progress.")
            return

        directory = filedialog.askdirectory()
        if directory:
            self.scan_in_progress = True
            self.suspicious_files.clear()
            self.result_tree.delete(*self.result_tree.get_children())
            self.scan_button.config(state=tk.DISABLED)
            self.progress_var.set(0)
            
            scan_thread = threading.Thread(target=self.perform_scan, args=(directory,))
            scan_thread.start()

    def perform_scan(self, directory):
        total_files = sum([len(files) for r, d, files in os.walk(directory)])
        scanned_files = 0

        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if self.is_suspicious(file_path):
                    self.suspicious_files.append(file_path)
                    self.master.after(0, self.update_result_tree, file_path, "Suspicious")
                else:
                    self.master.after(0, self.update_result_tree, file_path, "Clean")
                
                scanned_files += 1
                progress = (scanned_files / total_files) * 100
                self.master.after(0, self.update_progress, progress)

        self.master.after(0, self.finish_scan)

    def is_suspicious(self, file_path):
        suspicious_extensions = ['.exe', '.dll', '.bat', '.vbs']
        if any(file_path.lower().endswith(ext) for ext in suspicious_extensions):
            return True

        try:
            with open(file_path, 'rb') as file:
                content = file.read(1024)
                if b'virus' in content.lower() or b'malware' in content.lower():
                    return True
        except:
            pass

        return False

    def update_result_tree(self, file_path, status):
        self.result_tree.insert("", "end", values=(file_path, status))

    def update_progress(self, value):
        self.progress_var.set(value)

    def finish_scan(self):
        self.scan_in_progress = False
        self.scan_button.config(state=tk.NORMAL)
        messagebox.showinfo("Scan Complete", f"Scan completed. Found {len(self.suspicious_files)} suspicious files.")

    def quarantine_selected(self):
        selected_items = self.result_tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select files to quarantine.")
            return

        os.makedirs(self.quarantine_dir, exist_ok=True)

        for item in selected_items:
            file_path = self.result_tree.item(item)['values'][0]
            if file_path in self.suspicious_files:
                try:
                    quarantine_path = os.path.join(self.quarantine_dir, os.path.basename(file_path))
                    os.rename(file_path, quarantine_path)
                    self.result_tree.item(item, values=(quarantine_path, "Quarantined"))
                except Exception as e:
                    messagebox.showerror("Quarantine Error", f"Failed to quarantine {file_path}: {str(e)}")

        messagebox.showinfo("Quarantine Complete", "Selected files have been quarantined.")

    def show_quarantined_files(self):
        quarantine_window = tk.Toplevel(self.master)
        quarantine_window.title("Quarantined Files")
        quarantine_window.geometry("600x400")

        quarantine_tree = ttk.Treeview(quarantine_window, columns=("File",), show="headings")
        quarantine_tree.heading("File", text="Quarantined File")
        quarantine_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        if os.path.exists(self.quarantine_dir):
            for file in os.listdir(self.quarantine_dir):
                quarantine_tree.insert("", "end", values=(file,))
        else:
            quarantine_tree.insert("", "end", values=("No quarantined files found.",))

if __name__ == "__main__":
    root = tk.Tk()
    app = WhisperingGuardian(root)
    root.mainloop()
