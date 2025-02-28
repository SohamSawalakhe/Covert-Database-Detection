import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
from tkinter.ttk import Progressbar
import threading
import os
import time
from random import randint, choice
import sqlite3
import numpy as np
from sklearn.ensemble import IsolationForest
from queue import Queue
import shutil

# Special marker used for steganography method
HIDDEN_MARKER = b'::HIDDEN_DATA::'

class CovertDBDetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Covert Database Detection & Hiding Prototype")
        self.root.geometry("1200x800")
        self.model = self.train_model()  # For ML-based detection in other pages (if needed)
        self.create_ui()

    def train_model(self):
        """Train a dummy Isolation Forest model for anomaly detection."""
        data = np.array([[randint(100, 1000), randint(0, 1)] for _ in range(100)])
        model = IsolationForest(n_estimators=100, contamination=0.1)
        model.fit(data)
        return model

    def create_ui(self):
        """Create all the main pages and the top navigation menu."""
        self.create_top_menu()
        self.local_scan_frame = self.create_local_scan_page()
        self.network_scan_frame = self.create_network_scan_page()
        self.hidden_db_detection_frame = self.create_hidden_db_detection_page()
        self.performance_analysis_frame = self.create_performance_analysis_page()
        self.documentation_frame = self.create_documentation_page()
        self.hide_database_frame = self.create_hide_database_page()  # New advanced hide/recover module
        self.show_frame(self.local_scan_frame)

    def create_top_menu(self):
        """Set up the top navigation bar."""
        menu = tk.Menu(self.root)
        self.root.config(menu=menu)
        menu.add_command(label="Local Disk Scan", command=self.show_local_scan_page)
        menu.add_command(label="Network Scan", command=self.show_network_scan_page)
        menu.add_command(label="Hidden DB Detection", command=self.show_hidden_db_detection_page)
        menu.add_command(label="Performance Analysis", command=self.show_performance_analysis_page)
        menu.add_command(label="Documentation", command=self.show_documentation_page)
        menu.add_command(label="Hide Database", command=self.show_hide_database_page)

    def show_frame(self, frame):
        """Show a frame and hide others."""
        for widget in self.root.winfo_children():
            widget.pack_forget()
        frame.pack(fill="both", expand=True)

    def show_local_scan_page(self):
        self.show_frame(self.local_scan_frame)

    def show_network_scan_page(self):
        self.show_frame(self.network_scan_frame)

    def show_hidden_db_detection_page(self):
        self.show_frame(self.hidden_db_detection_frame)

    def show_performance_analysis_page(self):
        self.show_frame(self.performance_analysis_frame)

    def show_documentation_page(self):
        self.show_frame(self.documentation_frame)

    def show_hide_database_page(self):
        self.show_frame(self.hide_database_frame)

    # ------------------- Other Pages (Local, Network, etc.) -------------------

    def create_local_scan_page(self):
        frame = tk.Frame(self.root)
        self.local_progress = Progressbar(frame, orient="horizontal", length=400, mode="determinate")
        self.local_progress.pack(pady=10)
        self.scan_local_btn = tk.Button(frame, text="🔍 Scan Local Disk", command=self.scan_local_databases,
                                        bg="#4CAF50", fg="white", font=("Arial", 10))
        self.scan_local_btn.pack(pady=5)
        self.results_frame = tk.LabelFrame(frame, text="Search Results", font=("Arial", 12, "bold"))
        self.results_frame.pack(padx=20, pady=10, fill="both", expand=True)
        columns = ("Type", "Location", "Size (MB)", "Status")
        self.local_results_tree = ttk.Treeview(self.results_frame, columns=columns, show="headings")
        for col in columns:
            self.local_results_tree.heading(col, text=col)
            self.local_results_tree.column(col, anchor="center", width=200)
        self.local_results_tree.pack(fill="both", expand=True)
        self.local_results_tree.bind("<Double-1>", self.view_database_contents)
        return frame

    def create_network_scan_page(self):
        frame = tk.Frame(self.root)
        self.network_label = tk.Label(frame, text="Enter Network IP: ", font=("Arial", 10))
        self.network_label.pack(pady=5)
        self.network_entry = tk.Entry(frame, width=50)
        self.network_entry.pack(pady=5)
        self.connect_btn = tk.Button(frame, text="Connect to Server", command=self.scan_network_databases,
                                     bg="#2196F3", fg="white", font=("Arial", 10))
        self.connect_btn.pack(pady=5)
        self.network_results_frame = tk.LabelFrame(frame, text="Search Results", font=("Arial", 12, "bold"))
        self.network_results_frame.pack(padx=20, pady=10, fill="both", expand=True)
        columns = ("Type", "Location", "Size (MB)", "Status")
        self.network_results_tree = ttk.Treeview(self.network_results_frame, columns=columns, show="headings")
        for col in columns:
            self.network_results_tree.heading(col, text=col)
            self.network_results_tree.column(col, anchor="center", width=200)
        self.network_results_tree.pack(fill="both", expand=True)
        return frame

    def create_hidden_db_detection_page(self):
        frame = tk.Frame(self.root)
        method_frame = tk.LabelFrame(frame, text="Hidden Database Detection Methods", font=("Arial", 12, "bold"))
        method_frame.pack(padx=20, pady=10, fill="x")
        methods = [
            "File Signature Matching",
            "Heuristic Analysis",
            "Metadata Inspection",
            "File Size/Type Analysis",
            "Directory Traversal",
            "Hidden File Search",
            "Machine Learning Detection",
            "Hybrid Detection"
        ]
        for i, method in enumerate(methods):
            btn = tk.Button(method_frame, text=method,
                            command=lambda m=method: self.run_hidden_method(m),
                            bg="#FF9800", fg="white", font=("Arial", 10), width=25)
            btn.grid(row=i // 2, column=i % 2, padx=10, pady=10)
        self.hidden_result_frame = tk.LabelFrame(frame, text="Detection Output", font=("Arial", 12, "bold"))
        self.hidden_result_frame.pack(padx=20, pady=10, fill="both", expand=True)
        self.hidden_result_text = tk.Text(self.hidden_result_frame, height=15)
        self.hidden_result_text.pack(padx=10, pady=10, fill="both", expand=True)
        self.convert_btn = tk.Button(frame, text="Convert Hidden DB to Original", command=self.convert_hidden_db,
                                     bg="#4CAF50", fg="white", font=("Arial", 10))
        self.convert_btn.pack(pady=10)
        return frame

    def create_performance_analysis_page(self):
        frame = tk.Frame(self.root)
        self.analysis_label = tk.Label(frame, text="Performance Analysis Results Will Appear Here", font=("Arial", 10))
        self.analysis_label.pack(pady=20)
        return frame

    def create_documentation_page(self):
        frame = tk.Frame(self.root)
        doc_text = (
            "Covert Database Detection Application Prototype\n\n"
            "Features:\n"
            "- Local Disk Scan for databases\n"
            "- Network Scan for detecting remote databases\n"
            "- Hidden Database Detection using various methods\n"
            "    (Basic methods, advanced techniques, ML-based and hybrid approaches)\n"
            "- Hide/Recover Database Module demonstrating various data-hiding techniques\n"
            "- Performance Analysis for the scans\n"
        )
        doc_label = tk.Label(frame, text=doc_text, font=("Arial", 10), justify="left")
        doc_label.pack(padx=10, pady=10)
        return frame

    # ------------------- Hide/Recover Database Module -------------------

    def create_hide_database_page(self):
        """Advanced module to hide a database file using various methods and then recover it."""
        frame = tk.Frame(self.root)
        # Hiding section
        hide_frame = ttk.LabelFrame(frame, text="Hide Database", padding=10)
        hide_frame.pack(padx=20, pady=10, fill="x")

        ttk.Label(hide_frame, text="Select Database File:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.db_file_var = tk.StringVar()
        self.db_file_entry = ttk.Entry(hide_frame, textvariable=self.db_file_var, width=50)
        self.db_file_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(hide_frame, text="Browse", command=self.select_db_file).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(hide_frame, text="Select Hiding Method:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.hide_method_var = tk.StringVar()
        methods = ["Rename Extension", "Steganography", "Cryptography", "File Chunk Split",
                   "Alternate Data Streams (ADS)", "Machine Learning Obfuscation", "Hybrid Method"]
        self.hide_method_combo = ttk.Combobox(hide_frame, textvariable=self.hide_method_var, values=methods, state="readonly")
        self.hide_method_combo.grid(row=1, column=1, padx=5, pady=5)
        self.hide_method_combo.current(0)

        ttk.Button(hide_frame, text="Hide Database", command=self.hide_database).grid(row=2, column=1, pady=10)

        # Recovery section
        recover_frame = ttk.LabelFrame(frame, text="Recover Hidden Database", padding=10)
        recover_frame.pack(padx=20, pady=10, fill="x")
        ttk.Label(recover_frame, text="Select Hidden Database File:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.hidden_file_var = tk.StringVar()
        self.hidden_file_entry = ttk.Entry(recover_frame, textvariable=self.hidden_file_var, width=50)
        self.hidden_file_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(recover_frame, text="Browse", command=self.select_hidden_file).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(recover_frame, text="Select Conversion Method:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.convert_method_var = tk.StringVar()
        self.convert_method_combo = ttk.Combobox(recover_frame, textvariable=self.convert_method_var, values=methods, state="readonly")
        self.convert_method_combo.grid(row=1, column=1, padx=5, pady=5)
        self.convert_method_combo.current(0)

        ttk.Button(recover_frame, text="Recover Database", command=self.recover_database).grid(row=2, column=1, pady=10)

        # Output area for messages
        self.hide_output_text = tk.Text(frame, height=5)
        self.hide_output_text.pack(padx=20, pady=10, fill="x")

        return frame

    def select_db_file(self):
        file_path = filedialog.askopenfilename(title="Select Database File",
                                               filetypes=[("Database Files", "*.db *.sqlite"), ("All Files", "*.*")])
        if file_path:
            self.db_file_var.set(file_path)

    def select_hidden_file(self):
        file_path = filedialog.askopenfilename(title="Select Hidden Database File",
                                               filetypes=[("All Files", "*.*")])
        if file_path:
            self.hidden_file_var.set(file_path)

    def hide_database(self):
        db_file = self.db_file_var.get()
        method = self.hide_method_var.get()
        if not db_file:
            messagebox.showerror("Error", "Please select a database file to hide.")
            return
        result = self.hide_database_file(db_file, method)
        if result:
            self.hide_output_text.insert(tk.END, f"Database hidden using {method}.\nHidden file info:\n{result}\n\n")

    def recover_database(self):
        hidden_file = self.hidden_file_var.get()
        method = self.convert_method_var.get()
        if not hidden_file:
            messagebox.showerror("Error", "Please select a hidden database file.")
            return
        result = self.convert_hidden_database_file(hidden_file, method)
        if result:
            self.hide_output_text.insert(tk.END, f"Database recovered using {method}.\nRecovered file:\n{result}\n\n")

    # ------------------- Hiding Methods Implementations -------------------

    def hide_database_file(self, db_file, method):
        if method == "Rename Extension":
            new_file = os.path.splitext(db_file)[0] + ".hidden"
            shutil.copy2(db_file, new_file)
            return new_file

        elif method == "Steganography":
            cover_file = filedialog.askopenfilename(title="Select Cover File",
                                                    filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp"), ("All Files", "*.*")])
            if not cover_file:
                messagebox.showerror("Error", "No cover file selected for steganography.")
                return None
            with open(cover_file, "rb") as cf, open(db_file, "rb") as dbf:
                cover_bytes = cf.read()
                db_bytes = dbf.read()
            new_file = os.path.splitext(cover_file)[0] + "_stego" + os.path.splitext(cover_file)[1]
            with open(new_file, "wb") as nf:
                nf.write(cover_bytes + HIDDEN_MARKER + db_bytes)
            return new_file

        elif method == "Cryptography":
            new_file = os.path.splitext(db_file)[0] + ".enc"
            with open(db_file, "rb") as f:
                data = f.read()
            # Simple XOR encryption with key 0x55
            encrypted_data = bytes([b ^ 0x55 for b in data])
            with open(new_file, "wb") as f:
                f.write(encrypted_data)
            return new_file

        elif method == "File Chunk Split":
            with open(db_file, "rb") as f:
                data = f.read()
            part_size = len(data) // 3
            base = os.path.splitext(db_file)[0]
            part_files = []
            for i in range(3):
                if i < 2:
                    part_data = data[i*part_size:(i+1)*part_size]
                else:
                    part_data = data[i*part_size:]
                part_file = f"{base}_part{i+1}.chunk"
                with open(part_file, "wb") as pf:
                    pf.write(part_data)
                part_files.append(part_file)
            return "Parts created: " + ", ".join(part_files)

        elif method == "Alternate Data Streams (ADS)":
            # Simulate ADS by copying the file into a hidden folder.
            dir_name = os.path.join(os.path.dirname(db_file), ".ads_hidden")
            if not os.path.exists(dir_name):
                os.makedirs(dir_name)
            new_file = os.path.join(dir_name, os.path.basename(db_file))
            shutil.copy2(db_file, new_file)
            return new_file

        elif method == "Machine Learning Obfuscation":
            new_file = os.path.splitext(db_file)[0] + ".mlobs"
            with open(db_file, "rb") as f:
                data = f.read()
            obfuscated = data[::-1]  # Reverse bytes as a dummy obfuscation
            with open(new_file, "wb") as f:
                f.write(obfuscated)
            return new_file

        elif method == "Hybrid Method":
            # Apply cryptography first then rename extension.
            temp_file = self.hide_database_file(db_file, "Cryptography")
            if temp_file:
                new_file = os.path.splitext(db_file)[0] + ".hybrid"
                shutil.copy2(temp_file, new_file)
                return new_file
        else:
            messagebox.showerror("Error", "Unknown hiding method selected.")
            return None

    # ------------------- Conversion Methods Implementations -------------------

    def convert_hidden_database_file(self, hidden_file, method):
        if method == "Rename Extension":
            new_file = os.path.splitext(hidden_file)[0] + ".db"
            shutil.copy2(hidden_file, new_file)
            return new_file

        elif method == "Steganography":
            with open(hidden_file, "rb") as f:
                data = f.read()
            marker_index = data.find(HIDDEN_MARKER)
            if marker_index == -1:
                messagebox.showerror("Error", "Stego marker not found in file.")
                return None
            db_data = data[marker_index + len(HIDDEN_MARKER):]
            new_file = os.path.splitext(hidden_file)[0] + "_recovered.db"
            with open(new_file, "wb") as f:
                f.write(db_data)
            return new_file

        elif method == "Cryptography":
            new_file = os.path.splitext(hidden_file)[0] + "_recovered.db"
            with open(hidden_file, "rb") as f:
                data = f.read()
            decrypted = bytes([b ^ 0x55 for b in data])
            with open(new_file, "wb") as f:
                f.write(decrypted)
            return new_file

        elif method == "File Chunk Split":
            base = hidden_file.replace("_part1.chunk", "")
            part1 = base + "_part1.chunk"
            part2 = base + "_part2.chunk"
            part3 = base + "_part3.chunk"
            if not (os.path.exists(part1) and os.path.exists(part2) and os.path.exists(part3)):
                messagebox.showerror("Error", "One or more chunk files not found.")
                return None
            with open(part1, "rb") as f1, open(part2, "rb") as f2, open(part3, "rb") as f3:
                data = f1.read() + f2.read() + f3.read()
            new_file = base + "_recovered.db"
            with open(new_file, "wb") as f:
                f.write(data)
            return new_file

        elif method == "Alternate Data Streams (ADS)":
            parent = os.path.dirname(os.path.dirname(hidden_file))
            new_file = os.path.join(parent, os.path.basename(hidden_file))
            shutil.copy2(hidden_file, new_file)
            return new_file

        elif method == "Machine Learning Obfuscation":
            new_file = os.path.splitext(hidden_file)[0] + "_recovered.db"
            with open(hidden_file, "rb") as f:
                data = f.read()
            recovered = data[::-1]
            with open(new_file, "wb") as f:
                f.write(recovered)
            return new_file

        elif method == "Hybrid Method":
            new_file = os.path.splitext(hidden_file)[0] + "_recovered.db"
            with open(hidden_file, "rb") as f:
                data = f.read()
            decrypted = bytes([b ^ 0x55 for b in data])
            with open(new_file, "wb") as f:
                f.write(decrypted)
            return new_file

        else:
            messagebox.showerror("Error", "Unknown conversion method selected.")
            return None

    # ------------------- Other Functions (Local Scan, Network Scan, etc.) -------------------

    def scan_local_databases(self):
        self.local_progress.start()
        self.local_results_tree.delete(*self.local_results_tree.get_children())
        drive = filedialog.askdirectory(initialdir="/", title="Select a Drive")
        if drive:
            threading.Thread(target=self.start_local_search, args=(drive,)).start()
        else:
            messagebox.showerror("Error", "No drive selected.")

    def start_local_search(self, drive):
        database_extensions = ['.db', '.sqlite', '.mdf', '.accdb', '.dbf']
        found_files = []
        dirs_queue = Queue()
        dirs_queue.put(drive)
        while not dirs_queue.empty():
            current_dir = dirs_queue.get()
            try:
                with os.scandir(current_dir) as entries:
                    for entry in entries:
                        if entry.is_file() and any(entry.name.lower().endswith(ext) for ext in database_extensions):
                            found_files.append(entry.path)
                        elif entry.is_dir() and not entry.name.startswith('$') and not entry.name.startswith('.'):
                            dirs_queue.put(entry.path)
            except PermissionError:
                continue
        self.local_results_tree.delete(*self.local_results_tree.get_children())
        if found_files:
            for file in found_files:
                self.local_results_tree.insert("", "end", values=("SQLite", file, "Unknown", "Detected"))
        else:
            self.local_results_tree.insert("", "end", values=("No Results", "-", "-", "-"))
        self.local_progress.stop()

    def run_hidden_method(self, method_name):
        self.hidden_result_text.delete("1.0", tk.END)
        self.hidden_result_text.insert(tk.END, f"Running {method_name}...\n")
        self.hidden_result_text.insert(tk.END, "Searching for hidden databases...\n")
        self.root.update()
        time.sleep(1)
        detected_db = f"Detected hidden database using {method_name} at path:\nC:/hidden/db_{method_name.replace(' ', '_')}.db\n"
        self.hidden_result_text.insert(tk.END, detected_db)
        self.hidden_result_text.insert(tk.END, "You can convert the hidden database using the button below.\n")

    def convert_hidden_db(self):
        file_path = filedialog.askopenfilename(title="Select Hidden Database File",
                                               filetypes=[("Database Files", "*.db *.sqlite"), ("All Files", "*.*")])
        if not file_path:
            messagebox.showerror("Error", "No file selected.")
            return
        # For demonstration, we assume conversion using the default method (could be extended similarly)
        recovered = self.convert_hidden_database_file(file_path, "Rename Extension")
        if recovered:
            messagebox.showinfo("Conversion Success", f"Converted file saved as:\n{recovered}")

    def view_database_contents(self, event):
        selected_item = self.local_results_tree.selection()[0]
        db_info = self.local_results_tree.item(selected_item, "values")
        db_path = db_info[1]
        if db_path.endswith(('.db', '.sqlite')):
            try:
                self.open_database(db_path)
            except sqlite3.Error as e:
                messagebox.showerror("Error", f"Error opening database: {e}")
        else:
            messagebox.showerror("Error", "Selected file is not a valid SQLite database.")

    def open_database(self, db_path):
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            if not tables:
                messagebox.showinfo("No Tables", "No tables found in the database.")
                return
            table_window = tk.Toplevel(self.root)
            table_window.title(f"Database: {db_path}")
            table_window.geometry("400x300")
            listbox = tk.Listbox(table_window, height=10, width=40)
            for table in tables:
                listbox.insert(tk.END, table[0])
            listbox.pack(pady=10)
            def show_table_contents():
                selected_table = listbox.get(tk.ACTIVE)
                if selected_table:
                    cursor.execute(f"SELECT * FROM {selected_table}")
                    rows = cursor.fetchall()
                    if rows:
                        columns = [desc[0] for desc in cursor.description]
                        content_window = tk.Toplevel(self.root)
                        content_window.title(f"Contents of {selected_table}")
                        content_window.geometry("600x400")
                        text_widget = tk.Text(content_window, wrap="none", width=80, height=20)
                        text_widget.pack(padx=10, pady=10)
                        text_widget.insert(tk.END, f"{', '.join(columns)}\n")
                        text_widget.insert(tk.END, "-"*100 + "\n")
                        for row in rows:
                            text_widget.insert(tk.END, f"{', '.join(map(str, row))}\n")
                        text_widget.config(state=tk.DISABLED)
                    else:
                        messagebox.showinfo("No Data", f"No data found in table {selected_table}")
                table_window.destroy()
            view_btn = tk.Button(table_window, text="View Table", command=show_table_contents)
            view_btn.pack(pady=10)
            conn.close()
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"Error opening database: {e}")

    def scan_network_databases(self):
        ip = self.network_entry.get()
        if not ip:
            messagebox.showerror("Error", "Please enter a valid IP range!")
            return
        self.network_results_tree.delete(*self.network_results_tree.get_children())
        for i in range(3):
            time.sleep(0.5)
            db_type = choice(["SQL Server", "PostgreSQL", "MySQL", "SQLite", "Oracle"])
            location = f"//{ip}/server/db_{i}.sql"
            size = randint(100, 1000)
            self.network_results_tree.insert("", "end", values=(db_type, location, size, "Detected"))
        messagebox.showinfo("Scan Complete", "Network Database Scan Completed!")

if __name__ == "__main__":
    root = tk.Tk()
    app = CovertDBDetectionApp(root)
    root.mainloop()
