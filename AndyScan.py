import tkinter as tk
from tkinter import messagebox, filedialog
import subprocess
import shutil
import threading
import datetime
import os

class NetworkScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("AndyScan Network Scanner")
        self.root.geometry("600x500")
        
        # Create main frame
        self.main_frame = tk.Frame(root, padx=10, pady=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Input fields
        self.create_input_fields()
        
        # Buttons frame
        self.button_frame = tk.Frame(self.main_frame)
        self.button_frame.pack(fill=tk.X, pady=5)
        
        # Scan button
        self.scan_button = tk.Button(self.button_frame, text="Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        # Export button
        self.export_button = tk.Button(self.button_frame, text="Export Results", command=self.export_results)
        self.export_button.pack(side=tk.LEFT, padx=5)
        self.export_button.config(state=tk.DISABLED)
        
        # Clear button
        self.clear_button = tk.Button(self.button_frame, text="Clear", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Results area
        self.create_results_area()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = tk.Label(root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.scan_in_progress = False
        self.scan_results = ""

    def create_input_fields(self):
        # IP Range frame
        ip_frame = tk.Frame(self.main_frame)
        ip_frame.pack(fill=tk.X, pady=2)
        ip_label = tk.Label(ip_frame, text="IP Range:", width=10, anchor=tk.W)
        ip_label.pack(side=tk.LEFT)
        self.ip_entry = tk.Entry(ip_frame)
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Port Range frame
        port_frame = tk.Frame(self.main_frame)
        port_frame.pack(fill=tk.X, pady=2)
        port_label = tk.Label(port_frame, text="Port Range:", width=10, anchor=tk.W)
        port_label.pack(side=tk.LEFT)
        self.port_entry = tk.Entry(port_frame)
        self.port_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

    def create_results_area(self):
        # Create results frame with scrollbar
        results_frame = tk.Frame(self.main_frame)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        scrollbar = tk.Scrollbar(results_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.result_text = tk.Text(results_frame, height=20, yscrollcommand=scrollbar.set)
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar.config(command=self.result_text.yview)

    def check_zmap_installed(self):
        """Check if zmap is installed in the system."""
        if shutil.which('zmap') is None:
            messagebox.showerror("Error", "zmap is not installed on your system. Please install it before running the scan.")
            return False
        return True

    def validate_inputs(self):
        """Validate IP and port range inputs."""
        ip_range = self.ip_entry.get().strip()
        port_range = self.port_entry.get().strip()
        
        if not ip_range or not port_range:
            messagebox.showerror("Error", "Please enter both IP range and port range.")
            return False
        
        # Additional validation for zmap-specific format
        try:
            # Check if port is a single number or a range (e.g., 80 or 80-100)
            if '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
                if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
                    raise ValueError
            else:
                port = int(port_range)
                if not (0 <= port <= 65535):
                    raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Invalid port range. Please enter a valid port number (0-65535) or range (e.g., 80-100)")
            return False
            
        return True

    def start_scan(self):
        """Start the network scan in a separate thread."""
        if self.scan_in_progress:
            messagebox.showwarning("Warning", "A scan is already in progress!")
            return
            
        if not self.check_zmap_installed() or not self.validate_inputs():
            return
            
        self.scan_in_progress = True
        self.scan_button.config(state=tk.DISABLED)
        self.export_button.config(state=tk.DISABLED)
        self.status_var.set("Scanning in progress...")
        self.result_text.delete(1.0, tk.END)
        
        # Start scan in a separate thread
        scan_thread = threading.Thread(target=self.run_scan)
        scan_thread.daemon = True
        scan_thread.start()

    def run_scan(self):
        """Execute the network scan."""
        try:
            ip_range = self.ip_entry.get()
            port_range = self.port_entry.get()
            
            # Format command based on whether it's a single port or port range
            if '-' in port_range:
                start_port, end_port = port_range.split('-')
                command = f"zmap {ip_range} -p {start_port}:{end_port}"
            else:
                command = f"zmap {ip_range} -p {port_range}"
            
            # Add timestamp to results
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.result_text.insert(tk.END, f"Scan started at: {timestamp}\n")
            self.result_text.insert(tk.END, f"Command: {command}\n\n")
            
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Read output in real-time
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.result_text.insert(tk.END, output)
                    self.result_text.see(tk.END)
                    self.root.update_idletasks()
            
            # Get any errors
            _, stderr = process.communicate()
            if stderr:
                self.result_text.insert(tk.END, f"\nErrors:\n{stderr}")
            
            # Add completion timestamp
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.result_text.insert(tk.END, f"\nScan completed at: {timestamp}\n")
            
        except Exception as e:
            self.result_text.insert(tk.END, f"\nError occurred: {str(e)}\n")
        finally:
            self.scan_in_progress = False
            self.scan_button.config(state=tk.NORMAL)
            self.export_button.config(state=tk.NORMAL)
            self.status_var.set("Scan completed")
            self.root.update_idletasks()

    def export_results(self):
        """Export scan results to a text file."""
        if not self.result_text.get(1.0, tk.END).strip():
            messagebox.showwarning("Warning", "No results to export!")
            return
            
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"scan_results_{timestamp}.txt"
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=default_filename,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    file.write(self.result_text.get(1.0, tk.END))
                messagebox.showinfo("Success", "Results exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {str(e)}")

    def clear_results(self):
        """Clear the results text area."""
        self.result_text.delete(1.0, tk.END)
        self.status_var.set("Ready")
        self.export_button.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScanner(root)
    root.mainloop()
