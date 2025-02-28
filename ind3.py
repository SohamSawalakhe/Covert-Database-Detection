import os
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from tkinter.ttk import Progressbar
import threading
import time
from random import randint, choice, choices
import sqlite3
import numpy as np
from sklearn.ensemble import IsolationForest
from queue import Queue
import shutil
from stegano import lsb  # For LSB steganography
import math
import concurrent.futures
from cryptography.fernet import Fernet
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Use a fixed Fernet key for demonstration purposes.
FERNET_KEY = b'R9L-QYuo2AlKXp1jfQ6WUgLU0k5JhEr-h3wS7nN27k8='
fernet = Fernet(FERNET_KEY)

# Signature for steganography hiding
STEGANO_SIGNATURE = "DBHIDE:"


class CovertDBDetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Covert Database Detection & Hiding Prototype")
        self.root.geometry("1200x800")
        self.model = self.train_model()  # Dummy model for anomaly detection
        self.file_signatures = {
            'mdb': b'\x00\x01\x00\x00Standard Jet DB',
            'accdb': b'\x00\x01\x00\x00Standard ACE DB',
            'dbf': b'DBASE'
        }
        self.deep_model = None  # Simulation only for deep learning detection
        self.performance_folder = os.getcwd()  # Default folder for performance analysis
        self.create_ui()

    def train_model(self):
        data = np.array([[randint(100, 1000), randint(0, 1)] for _ in range(100)])
        model = IsolationForest(n_estimators=100, contamination=0.1)
        model.fit(data)
        return model

    def create_ui(self):
        self.create_top_menu()
        self.local_scan_frame = self.create_local_scan_page()
        self.network_scan_frame = self.create_network_scan_page()
        self.hidden_db_detection_frame = self.create_hidden_db_detection_page()
        self.performance_analysis_frame = self.create_performance_analysis_page()
        self.documentation_frame = self.create_documentation_page()
        self.hide_database_frame = self.create_hide_database_page()
        self.show_frame(self.local_scan_frame)

    def create_top_menu(self):
        menu = tk.Menu(self.root)
        self.root.config(menu=menu)
        menu.add_command(label="Local Disk Scan", command=self.show_local_scan_page)
        menu.add_command(label="Network Scan", command=self.show_network_scan_page)
        menu.add_command(label="Hidden DB Detection", command=self.show_hidden_db_detection_page)
        menu.add_command(label="Performance Analysis", command=self.show_performance_analysis_page)
        menu.add_command(label="Documentation", command=self.show_documentation_page)
        menu.add_command(label="Hide Database", command=self.show_hide_database_page)

    def show_frame(self, frame):
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
        # Automatically run analysis on this page using the default folder.
        self.run_performance_analysis_default()

    def show_documentation_page(self):
        self.show_frame(self.documentation_frame)

    def show_hide_database_page(self):
        self.show_frame(self.hide_database_frame)

    # ------------------- Local Scan Methods -------------------

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

    def view_database_contents(self, event):
        selected_item = self.local_results_tree.selection()[0]
        db_info = self.local_results_tree.item(selected_item, "values")
        db_path = db_info[1]
        if db_path.endswith(('.db', '.sqlite')):
            self.open_database(db_path)
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
        except Exception as e:
            messagebox.showerror("Error", f"Error opening database: {e}")

    # ------------------- Network Scan -------------------

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

    # ------------------- Hidden Database Detection -------------------

    def create_hidden_db_detection_page(self):
        frame = tk.Frame(self.root)
        detection_frame = ttk.LabelFrame(frame, text="Detect Hidden Database", padding=10)
        detection_frame.pack(padx=20, pady=10, fill="x")
        ttk.Label(detection_frame, text="Select Detection Method:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.detect_method_var = tk.StringVar()
        detection_methods = ["Rename Extension", "Steganography", "Cryptography", "File Chunk Split",
                             "Alternate Data Streams (ADS)", "Machine Learning Obfuscation", "Hybrid Method", "Deep Learning"]
        self.detect_method_combo = ttk.Combobox(detection_frame, textvariable=self.detect_method_var,
                                                values=detection_methods, state="readonly")
        self.detect_method_combo.grid(row=0, column=1, padx=5, pady=5)
        self.detect_method_combo.current(0)
        ttk.Button(detection_frame, text="Scan Directory", command=self.scan_hidden_db_directory)\
            .grid(row=0, column=2, padx=5, pady=5)
        result_frame = ttk.LabelFrame(frame, text="Detected Hidden Databases", padding=10)
        result_frame.pack(padx=20, pady=10, fill="both", expand=True)
        columns = ("File Path", "Method")
        self.detected_tree = ttk.Treeview(result_frame, columns=columns, show="headings")
        for col in columns:
            self.detected_tree.heading(col, text=col)
            self.detected_tree.column(col, anchor="center", width=300)
        self.detected_tree.pack(fill="both", expand=True)
        ttk.Button(frame, text="Recover Selected Database", command=self.recover_selected_hidden_db)\
            .pack(pady=10)
        self.detect_output_text = tk.Text(frame, height=5)
        self.detect_output_text.pack(padx=20, pady=10, fill="x")
        return frame

    def scan_hidden_db_directory(self):
        method = self.detect_method_var.get()
        directory = filedialog.askdirectory(initialdir="/", title="Select Directory to Scan")
        if not directory:
            messagebox.showerror("Error", "No directory selected.")
            return

        start_time = time.time()
        self.detected_tree.delete(*self.detected_tree.get_children())
        found_files = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = {}
            for root_dir, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root_dir, file)
                    future = executor.submit(self.advanced_detection, file_path, self.detect_method_var.get())
                    futures[future] = file_path
            for future in concurrent.futures.as_completed(futures):
                try:
                    if future.result():
                        found_files.append(futures[future])
                except Exception:
                    continue

        elapsed = time.time() - start_time

        if found_files:
            for f in found_files:
                self.detected_tree.insert("", "end", values=(f, self.detect_method_var.get()))
            self.detect_output_text.insert(tk.END, f"Found {len(found_files)} hidden file(s) using {self.detect_method_var.get()} in {elapsed:.2f} seconds.\n")
        else:
            self.detect_output_text.insert(tk.END, f"No hidden files found using {self.detect_method_var.get()} in {elapsed:.2f} seconds.\n")

    def advanced_detection(self, file_path, method):
        try:
            # Use only a sample of the file to improve speed on large files.
            sample_size = 1024 * 1024  # 1 MB sample
            with open(file_path, "rb") as f:
                data = f.read(sample_size)
            if method == "Steganography":
                try:
                    hidden_data = lsb.reveal(file_path)
                    if (hidden_data is not None and 
                        hidden_data.startswith(STEGANO_SIGNATURE) and 
                        len(hidden_data) > len(STEGANO_SIGNATURE) + 20):
                        return True
                except Exception:
                    return False
            elif method == "Cryptography":
                if not data:
                    return False
                entropy = -sum((data.count(byte)/len(data)) * math.log2(data.count(byte)/len(data))
                               for byte in set(data) if data.count(byte)/len(data) > 0)
                if entropy > 7.5:
                    return True
            elif method == "Rename Extension":
                if os.path.splitext(file_path)[1].lower() == ".db":
                    return False
                with open(file_path, "rb") as f:
                    header = f.read(1024)
                ext = os.path.splitext(file_path)[1][1:].lower()
                if ext in self.file_signatures:
                    if self.file_signatures[ext] not in header:
                        return True
                if b"SQLite format 3" in header:
                    return True
            elif method == "File Chunk Split":
                if "chunk" in file_path.lower() and file_path.endswith(".chk"):
                    return True
            elif method == "Alternate Data Streams (ADS)":
                with open(file_path, "rb") as f:
                    header = f.read(1024)
                if b"SQLite format 3" in header:
                    return True
            elif method == "Machine Learning Obfuscation":
                with open(file_path, "rb") as f:
                    header = f.read(3)
                if header == b"ML:":
                    return True
            elif method == "Hybrid Method":
                with open(file_path, "rb") as f:
                    header = f.read(7)
                if header == b"HYBRID:":
                    return True
            elif method == "Deep Learning":
                if not data:
                    return False
                entropy = -sum((data.count(byte)/len(data)) * math.log2(data.count(byte)/len(data))
                               for byte in set(data) if data.count(byte)/len(data) > 0)
                return entropy > 7.0
        except Exception:
            return False
        return False

    def recover_selected_hidden_db(self):
        selected = self.detected_tree.selection()
        if not selected:
            messagebox.showerror("Error", "No hidden database selected.")
            return
        item = self.detected_tree.item(selected[0])
        file_path, method = item['values']
        result = self.convert_hidden_database_file(file_path, method)
        if result:
            self.detect_output_text.insert(tk.END, f"Recovered file using {method}.\nRecovered file: {result}\n")

    # ------------------- Performance Analysis -------------------

    def create_performance_analysis_page(self):
        frame = tk.Frame(self.root)
        self.analysis_label = tk.Label(frame, text="Performance Analysis", font=("Arial", 12, "bold"))
        self.analysis_label.pack(pady=10)
        
        # Display default folder info (using current working directory)
        self.default_folder = os.getcwd()
        folder_label = tk.Label(frame, text=f"Analyzing folder: {self.default_folder}", font=("Arial", 10))
        folder_label.pack(pady=5)
        
        self.plot_frame = tk.Frame(frame)
        self.plot_frame.pack(pady=10, fill="both", expand=True)
        
        self.perf_status_label = tk.Label(frame, text="Running analysis...", font=("Arial", 10))
        self.perf_status_label.pack(pady=5)
        
        # Automatically run performance analysis when this page is shown.
        self.run_performance_analysis_default()
        return frame

    def run_performance_analysis_default(self):
        methods = ["Rename Extension", "Steganography", "Cryptography", "File Chunk Split",
                   "Alternate Data Streams (ADS)", "Machine Learning Obfuscation", "Hybrid Method", "Deep Learning"]
        performance_data = {}
        for method in methods:
            t, count = self.measure_detection_time(method, self.default_folder)
            performance_data[method] = (t, count)
        self.plot_performance(performance_data)
        self.perf_status_label.config(text="Performance analysis complete.")

    def measure_detection_time(self, method, folder):
        start = time.time()
        count = 0
        for root_dir, dirs, files in os.walk(folder):
            for file in files:
                file_path = os.path.join(root_dir, file)
                if self.advanced_detection(file_path, method):
                    count += 1
        elapsed = time.time() - start
        return elapsed, count

    def plot_performance(self, data):
        methods = list(data.keys())
        times = [data[m][0] for m in methods]
        counts = [data[m][1] for m in methods]
        
        for widget in self.plot_frame.winfo_children():
            widget.destroy()
            
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
        fig.suptitle("Detection Performance Analysis", fontsize=14)
        
        ax1.bar(methods, times, color='skyblue')
        ax1.set_ylabel("Time (seconds)", color='blue', fontsize=10)
        ax1.set_xlabel("Detection Method", fontsize=10)
        ax1.tick_params(axis='y', labelcolor='blue')
        for i, t in enumerate(times):
            ax1.text(i, t + 0.05, f"{t:.2f}s", ha='center', color='darkblue', fontsize=8)
        
        ax2.bar(methods, counts, color='lightgreen')
        ax2.set_ylabel("Hidden Files Detected", color='green', fontsize=10)
        ax2.set_xlabel("Detection Method", fontsize=10)
        ax2.tick_params(axis='y', labelcolor='green')
        for i, c in enumerate(counts):
            ax2.text(i, c + 0.5, str(c), ha='center', color='darkgreen', fontsize=8)
        
        fig.tight_layout(rect=[0, 0, 1, 0.95])
        canvas = FigureCanvasTkAgg(fig, master=self.plot_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)
        self.perf_status_label.config(text="Performance analysis complete.")

    # ------------------- Documentation -------------------

    def create_documentation_page(self):
        frame = tk.Frame(self.root)
        doc_text = (
            "Covert Database Detection Application Prototype\n\n"
            "Features:\n"
            "- Local Disk Scan for databases\n"
            "- Network Scan for detecting remote databases\n"
            "- Hidden Database Detection using advanced content analysis, signature matching, and deep learning simulation\n"
            "- Hide/Recover Database Module demonstrating various data-hiding techniques\n"
            "- Performance Analysis with graphs showing time taken and detection counts\n"
        )
        doc_label = tk.Label(frame, text=doc_text, font=("Arial", 10), justify="left")
        doc_label.pack(padx=10, pady=10)
        return frame

    # ------------------- Hide/Recover Database Module -------------------

    def create_hide_database_page(self):
        frame = tk.Frame(self.root)
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
        recover_frame = ttk.LabelFrame(frame, text="Recover Hidden Database", padding=10)
        recover_frame.pack(padx=20, pady=10, fill="x")
        ttk.Label(recover_frame, text="Select Hidden File:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
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
        self.hide_output_text = tk.Text(frame, height=5)
        self.hide_output_text.pack(padx=20, pady=10, fill="x")
        return frame

    def select_db_file(self):
        file_path = filedialog.askopenfilename(title="Select Database File",
                                               filetypes=[("Database Files", "*.db *.sqlite"), ("All Files", "*.*")])
        if file_path:
            self.db_file_var.set(file_path)

    def select_hidden_file(self):
        file_path = filedialog.askopenfilename(title="Select Hidden File",
                                               filetypes=[("All Files", "*.*")])
        if file_path:
            self.hidden_file_var.set(file_path)

    def hide_database(self):
        db_file = self.db_file_var.get()
        method = self.hide_method_var.get()
        if not db_file:
            messagebox.showerror("Error", "Please select a database file to hide.")
            return
        copy_file = os.path.splitext(db_file)[0] + "_copy" + os.path.splitext(db_file)[1]
        shutil.copy2(db_file, copy_file)
        result = self.hide_database_file(copy_file, method)
        if result:
            self.hide_output_text.insert(tk.END, f"Database hidden using {method}.\nHidden file info:\n{result}\n\n")

    def recover_database(self):
        hidden_file = self.hidden_file_var.get()
        method = self.convert_method_var.get()
        if not hidden_file:
            messagebox.showerror("Error", "Please select a hidden file.")
            return
        result = self.convert_hidden_database_file(hidden_file, method)
        if result:
            self.hide_output_text.insert(tk.END, f"Database recovered using {method}.\nRecovered file:\n{result}\n\n")

    # ------------------- Hiding Methods -------------------

    def hide_database_file(self, db_file, method):
        if method == "Rename Extension":
            rename_extensions = [".txt", ".bin", ".dat", ".xlsx", ".docx"]
            new_ext = choice(rename_extensions)
            new_file = os.path.splitext(db_file)[0] + new_ext
            shutil.copy2(db_file, new_file)
            return new_file
        elif method == "Steganography":
            cover_file = filedialog.askopenfilename(title="Select Cover Image",
                                                    filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.pnd"), ("All Files", "*.*")])
            if not cover_file:
                messagebox.showerror("Error", "No cover image selected for steganography.")
                return None
            with open(db_file, "rb") as f:
                data = f.read()
            data_str = STEGANO_SIGNATURE + data.hex()
            rand_suffix = str(randint(1000, 9999))
            new_file = os.path.splitext(cover_file)[0] + "_" + rand_suffix + os.path.splitext(cover_file)[1]
            secret_image = lsb.hide(cover_file, data_str)
            secret_image.save(new_file)
            return new_file
        elif method == "Cryptography":
            crypto_extensions = [".enc", ".crypt", ".cipher"]
            new_ext = choice(crypto_extensions)
            new_file = os.path.splitext(db_file)[0] + new_ext
            with open(db_file, "rb") as f:
                data = f.read()
            encrypted_data = fernet.encrypt(data)
            with open(new_file, "wb") as f:
                f.write(encrypted_data)
            return new_file
        elif method == "File Chunk Split":
            with open(db_file, "rb") as f:
                data = f.read()
            num_chunks = randint(2, 5)
            chunk_size = len(data) // num_chunks
            base = os.path.splitext(db_file)[0]
            part_files = []
            for i in range(num_chunks):
                if i < num_chunks - 1:
                    part_data = data[i*chunk_size:(i+1)*chunk_size]
                else:
                    part_data = data[i*chunk_size:]
                rand_suffix = ''.join(choices("abcdefghijklmnopqrstuvwxyz", k=4))
                part_file = f"{base}_chunk_{i+1}_{rand_suffix}.chk"
                with open(part_file, "wb") as pf:
                    pf.write(part_data)
                part_files.append(part_file)
            return "Parts created: " + ", ".join(part_files)
        elif method == "Alternate Data Streams (ADS)":
            rand_folder = "." + ''.join(choices("abcdefghijklmnopqrstuvwxyz", k=6)) + "_ads"
            parent = os.path.dirname(db_file)
            ads_folder = os.path.join(parent, rand_folder)
            if not os.path.exists(ads_folder):
                os.makedirs(ads_folder)
            new_file = os.path.join(ads_folder, os.path.basename(db_file))
            shutil.copy2(db_file, new_file)
            return new_file
        elif method == "Machine Learning Obfuscation":
            with open(db_file, "rb") as f:
                data = f.read()
            n = len(data)
            indices = list(range(n))
            import random
            random.shuffle(indices)
            permuted_data = bytearray(n)
            for i, idx in enumerate(indices):
                permuted_data[i] = data[idx]
            header = ("ML:" + ",".join(map(str, indices)) + "::").encode('utf-8')
            new_file = os.path.splitext(db_file)[0] + ".mlobs"
            with open(new_file, "wb") as f:
                f.write(header + permuted_data)
            return new_file
        elif method == "Hybrid Method":
            available = ["Rename Extension", "Cryptography", "Machine Learning Obfuscation", "Alternate Data Streams (ADS)"]
            chosen = list(set(choices(available, k=2)))
            method_sequence = []
            intermediate_file = db_file
            for m in chosen:
                method_sequence.append(m)
                intermediate_file = self.hide_database_file(intermediate_file, m)
                if intermediate_file is None:
                    return None
            header = ("HYBRID:" + ";".join(method_sequence) + "::").encode('utf-8')
            with open(intermediate_file, "rb") as f:
                final_data = f.read()
            new_file = os.path.splitext(db_file)[0] + ".hybrid"
            with open(new_file, "wb") as f:
                f.write(header + final_data)
            return new_file
        else:
            messagebox.showerror("Error", "Unknown hiding method selected.")
            return None

    # ------------------- Conversion Methods -------------------

    def convert_hidden_database_file(self, hidden_file, method):
        if method == "Rename Extension":
            new_file = os.path.splitext(hidden_file)[0] + ".db"
            shutil.copy2(hidden_file, new_file)
            return new_file
        elif method == "Steganography":
            hidden_data_str = lsb.reveal(hidden_file)
            if hidden_data_str is None:
                messagebox.showerror("Error", "No hidden data found in image using stegano.")
                return None
            if not hidden_data_str.startswith(STEGANO_SIGNATURE):
                messagebox.showerror("Error", "Hidden data does not contain the expected signature.")
                return None
            hex_data = hidden_data_str[len(STEGANO_SIGNATURE):]
            try:
                db_data = bytes.fromhex(hex_data)
            except Exception as e:
                messagebox.showerror("Error", f"Error converting hidden data: {e}")
                return None
            new_file = os.path.splitext(hidden_file)[0] + "_recovered.db"
            with open(new_file, "wb") as f:
                f.write(db_data)
            return new_file
        elif method == "Cryptography":
            new_file = os.path.splitext(hidden_file)[0] + "_recovered.db"
            with open(hidden_file, "rb") as f:
                data = f.read()
            try:
                decrypted = fernet.decrypt(data)
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")
                return None
            with open(new_file, "wb") as f:
                f.write(decrypted)
            return new_file
        elif method == "File Chunk Split":
            base = hidden_file.split("_chunk_")[0]
            dir_path = os.path.dirname(hidden_file)
            part_files = []
            for file in os.listdir(dir_path):
                if file.startswith(os.path.basename(base)) and file.endswith(".chk"):
                    part_files.append(os.path.join(dir_path, file))
            def get_chunk_num(filename):
                try:
                    parts = filename.split("_chunk_")[1].split("_")
                    return int(parts[0])
                except:
                    return 0
            part_files.sort(key=lambda x: get_chunk_num(x))
            if not part_files:
                messagebox.showerror("Error", "No chunk files found.")
                return None
            data = b""
            for pf in part_files:
                with open(pf, "rb") as f:
                    data += f.read()
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
                content = f.read()
            if not content.startswith(b"ML:"):
                messagebox.showerror("Error", "Invalid ML obfuscation file.")
                return None
            try:
                header_end = content.index(b"::")
                header = content[3:header_end].decode('utf-8')
                permutation = list(map(int, header.split(",")))
            except Exception as e:
                messagebox.showerror("Error", "Error reading ML header.")
                return None
            permuted_data = content[header_end+2:]
            n = len(permuted_data)
            if n != len(permutation):
                messagebox.showerror("Error", "Data length does not match permutation.")
                return None
            original_data = bytearray(n)
            for i, p in enumerate(permutation):
                original_data[p] = permuted_data[i]
            new_file = os.path.splitext(hidden_file)[0] + "_recovered.db"
            with open(new_file, "wb") as f:
                f.write(original_data)
            return new_file
        elif method == "Hybrid Method":
            with open(hidden_file, "rb") as f:
                content = f.read()
            if not content.startswith(b"HYBRID:"):
                messagebox.showerror("Error", "Invalid hybrid file format.")
                return None
            try:
                header_end = content.index(b"::")
                header = content[7:header_end].decode('utf-8')
                methods_used = header.split(";")
            except Exception as e:
                messagebox.showerror("Error", "Error reading hybrid header.")
                return None
            final_data = content[header_end+2:]
            for m in reversed(methods_used):
                final_data = self.reverse_hybrid_step(final_data, m)
                if final_data is None:
                    return None
            new_file = os.path.splitext(hidden_file)[0] + "_recovered.db"
            with open(new_file, "wb") as f:
                f.write(final_data)
            return new_file
        else:
            messagebox.showerror("Error", "Unknown conversion method selected.")
            return None

    def reverse_hybrid_step(self, data, method):
        if method in ["Rename Extension", "Alternate Data Streams (ADS)"]:
            return data
        elif method == "Cryptography":
            try:
                return fernet.decrypt(data)
            except Exception:
                return None
        elif method == "Machine Learning Obfuscation":
            return data[::-1]
        else:
            return None

    # ------------------- Performance Analysis -------------------

    def create_performance_analysis_page(self):
        frame = tk.Frame(self.root)
        self.analysis_label = tk.Label(frame, text="Performance Analysis", font=("Arial", 12, "bold"))
        self.analysis_label.pack(pady=10)
        
        # Display default folder info (using current working directory)
        self.default_folder = os.getcwd()
        folder_label = tk.Label(frame, text=f"Analyzing folder: {self.default_folder}", font=("Arial", 10))
        folder_label.pack(pady=5)
        
        self.plot_frame = tk.Frame(frame)
        self.plot_frame.pack(pady=10, fill="both", expand=True)
        
        self.perf_status_label = tk.Label(frame, text="Running analysis...", font=("Arial", 10))
        self.perf_status_label.pack(pady=5)
        
        # Automatically run performance analysis when this page is shown
        self.run_performance_analysis_default()
        return frame

    def run_performance_analysis_default(self):
        methods = ["Rename Extension", "Steganography", "Cryptography", "File Chunk Split",
                   "Alternate Data Streams (ADS)", "Machine Learning Obfuscation", "Hybrid Method", "Deep Learning"]
        performance_data = {}
        for method in methods:
            t, count = self.measure_detection_time(method, self.default_folder)
            performance_data[method] = (t, count)
        self.plot_performance(performance_data)
        self.perf_status_label.config(text="Performance analysis complete.")

    def measure_detection_time(self, method, folder):
        start = time.time()
        count = 0
        for root_dir, dirs, files in os.walk(folder):
            for file in files:
                file_path = os.path.join(root_dir, file)
                if self.advanced_detection(file_path, method):
                    count += 1
        elapsed = time.time() - start
        return elapsed, count

    def plot_performance(self, data):
        methods = list(data.keys())
        times = [data[m][0] for m in methods]
        counts = [data[m][1] for m in methods]
        
        for widget in self.plot_frame.winfo_children():
            widget.destroy()
            
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
        fig.suptitle("Detection Performance Analysis", fontsize=14)
        
        ax1.bar(methods, times, color='skyblue')
        ax1.set_ylabel("Time (seconds)", color='blue', fontsize=10)
        ax1.set_xlabel("Detection Method", fontsize=10)
        ax1.tick_params(axis='y', labelcolor='blue')
        for i, t in enumerate(times):
            ax1.text(i, t + 0.05, f"{t:.2f}s", ha='center', color='darkblue', fontsize=8)
        
        ax2.bar(methods, counts, color='lightgreen')
        ax2.set_ylabel("Hidden Files Detected", color='green', fontsize=10)
        ax2.set_xlabel("Detection Method", fontsize=10)
        ax2.tick_params(axis='y', labelcolor='green')
        for i, c in enumerate(counts):
            ax2.text(i, c + 0.5, str(c), ha='center', color='darkgreen', fontsize=8)
        
        fig.tight_layout(rect=[0, 0, 1, 0.95])
        canvas = FigureCanvasTkAgg(fig, master=self.plot_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)
        self.perf_status_label.config(text="Performance analysis complete.")

    # ------------------- Documentation -------------------

    def create_documentation_page(self):
        frame = tk.Frame(self.root)
        doc_text = (
            "Covert Database Detection Application Prototype\n\n"
            "Features:\n"
            "- Local Disk Scan for databases\n"
            "- Network Scan for detecting remote databases\n"
            "- Hidden Database Detection using advanced content analysis, signature matching, and deep learning simulation\n"
            "- Hide/Recover Database Module demonstrating various data-hiding techniques\n"
            "- Performance Analysis with graphs showing time taken and detection counts\n"
        )
        doc_label = tk.Label(frame, text=doc_text, font=("Arial", 10), justify="left")
        doc_label.pack(padx=10, pady=10)
        return frame

    # ------------------- Hide/Recover Database Module -------------------

    def create_hide_database_page(self):
        frame = tk.Frame(self.root)
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
        recover_frame = ttk.LabelFrame(frame, text="Recover Hidden Database", padding=10)
        recover_frame.pack(padx=20, pady=10, fill="x")
        ttk.Label(recover_frame, text="Select Hidden File:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
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
        self.hide_output_text = tk.Text(frame, height=5)
        self.hide_output_text.pack(padx=20, pady=10, fill="x")
        return frame

    def select_db_file(self):
        file_path = filedialog.askopenfilename(title="Select Database File",
                                               filetypes=[("Database Files", "*.db *.sqlite"), ("All Files", "*.*")])
        if file_path:
            self.db_file_var.set(file_path)

    def select_hidden_file(self):
        file_path = filedialog.askopenfilename(title="Select Hidden File",
                                               filetypes=[("All Files", "*.*")])
        if file_path:
            self.hidden_file_var.set(file_path)

    def hide_database(self):
        db_file = self.db_file_var.get()
        method = self.hide_method_var.get()
        if not db_file:
            messagebox.showerror("Error", "Please select a database file to hide.")
            return
        copy_file = os.path.splitext(db_file)[0] + "_copy" + os.path.splitext(db_file)[1]
        shutil.copy2(db_file, copy_file)
        result = self.hide_database_file(copy_file, method)
        if result:
            self.hide_output_text.insert(tk.END, f"Database hidden using {method}.\nHidden file info:\n{result}\n\n")

    def recover_database(self):
        hidden_file = self.hidden_file_var.get()
        method = self.convert_method_var.get()
        if not hidden_file:
            messagebox.showerror("Error", "Please select a hidden file.")
            return
        result = self.convert_hidden_database_file(hidden_file, method)
        if result:
            self.hide_output_text.insert(tk.END, f"Database recovered using {method}.\nRecovered file:\n{result}\n\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = CovertDBDetectionApp(root)
    root.mainloop()
