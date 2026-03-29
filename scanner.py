import socket
import threading
import time
import queue
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------
# Service Map
# ---------------------------
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'RPC', 139: 'NetBIOS',
    143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
}

# Specific port lists for different scan types
PORT_LISTS = {
    'common': list(range(1, 1025)),  # 1-1024
    'web': [80, 443, 8080, 8443, 8000, 3000, 5000, 8888],
    'database': [1433, 3306, 5432, 27017, 6379, 9200],
    'mail': [25, 110, 143, 465, 587, 993, 995],
    'full': None  # Will be range-based
}

# ---------------------------
# Enhanced Scanner Worker
# ---------------------------
class PortScanner:
    def __init__(self, target, start_port, end_port, timeout=1.0, max_workers=100):
        """
        Initialize scanner with port range
        """
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_workers = max_workers
        self._stop_event = threading.Event()
        
        # Create list of ports to scan
        self.ports_to_scan = list(range(self.start_port, self.end_port + 1))
        self.total_ports = len(self.ports_to_scan)
        self.scanned_count = 0
        self.open_ports = []
        self.filtered_ports = []  # Track filtered/timeout ports
        self._lock = threading.Lock()
        self.result_queue = queue.Queue()
        self.start_time = None
        self.scan_speed = 0  # ports per second
        self.last_update_time = None
        self.last_scanned_count = 0
        
    def stop(self):
        """Stop the scanning process"""
        self._stop_event.set()
        
    def scan_port(self, port):
        """Scan a single port with improved detection"""
        if self._stop_event.is_set():
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Start time for this port
            start_time = time.time()
            result = sock.connect_ex((self.target, port))
            elapsed = time.time() - start_time
            
            sock.close()
            
            if result == 0:  # Port is open
                service = COMMON_PORTS.get(port, 'Unknown')
                return ('open', port, service, elapsed)
            elif result == 111 or result == 10061:  # Connection refused (closed)
                return ('closed', port, None, elapsed)
            else:
                # Other errors (filtered, unreachable)
                return ('filtered', port, None, elapsed)
                
        except socket.timeout:
            return ('filtered', port, None, self.timeout)
        except Exception:
            return ('error', port, None, 0)
            
    def resolve_target(self):
        """Resolve hostname to IP"""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            return None
            
    def run(self):
        """Run the scanner with improved accuracy"""
        self.start_time = time.time()
        self.last_update_time = self.start_time
        self.last_scanned_count = 0
        
        # Check if target is resolvable
        resolved_ip = self.resolve_target()
        if not resolved_ip:
            self.result_queue.put(('error', f"Could not resolve hostname: {self.target}", None))
            self.result_queue.put(('done', None, None))
            return
            
        # Update target to resolved IP for consistency
        self.target = resolved_ip
        
        # Scan with ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            futures = {}
            for port in self.ports_to_scan:
                if self._stop_event.is_set():
                    break
                futures[executor.submit(self.scan_port, port)] = port
            
            # Process results as they complete
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    break
                    
                result = future.result()
                if result:
                    status, port, service, elapsed = result
                    
                    with self._lock:
                        self.scanned_count += 1
                        
                        if status == 'open':
                            self.open_ports.append((port, service, elapsed))
                            self.result_queue.put(('open', port, service))
                        elif status == 'filtered':
                            self.filtered_ports.append((port, elapsed))
                        
                        # Calculate scan speed every 50 ports
                        if self.scanned_count % 50 == 0:
                            now = time.time()
                            time_diff = now - self.last_update_time
                            ports_diff = self.scanned_count - self.last_scanned_count
                            if time_diff > 0:
                                self.scan_speed = ports_diff / time_diff
                            self.last_update_time = now
                            self.last_scanned_count = self.scanned_count
                    
                    self.result_queue.put(('progress', self.scanned_count, self.total_ports))
        
        # Signal completion
        self.result_queue.put(('done', None, None))
        
    def get_open_ports_sorted(self):
        """Return sorted open ports"""
        return sorted(self.open_ports, key=lambda x: x[0])
    
    def get_filtered_count(self):
        """Get count of filtered ports"""
        return len(self.filtered_ports)
    
    def get_scan_duration(self):
        """Get scan duration in seconds"""
        if self.start_time:
            return time.time() - self.start_time
        return 0
    
    def get_scan_stats(self):
        """Get scan statistics"""
        duration = self.get_scan_duration()
        open_count = len(self.open_ports)
        filtered_count = len(self.filtered_ports)
        closed_count = self.total_ports - open_count - filtered_count
        
        return {
            'total': self.total_ports,
            'open': open_count,
            'closed': closed_count,
            'filtered': filtered_count,
            'duration': duration,
            'speed': self.scan_speed if self.scan_speed > 0 else (self.total_ports / duration if duration > 0 else 0)
        }

# ---------------------------
# Improved GUI Application
# ---------------------------
class Network_Port_Scanner_GUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Port Scanner")
        self.geometry("1000x750")
        self.resizable(True, True)
        
        self.scanner = None
        self.scanner_thread = None
        self.is_scanning = False
        self.elapsed_time_id = None
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main container
        main_container = ttk.Frame(self, padding="10")
        main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        main_container.columnconfigure(0, weight=1)
        main_container.rowconfigure(5, weight=1)  # Changed to row 5 where results are
        
        # Title
        title_label = ttk.Label(main_container, text="Network Port Scanner", 
                                font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, pady=(0, 10))
        
        # Input Frame
        input_frame = ttk.LabelFrame(main_container, text="Target Configuration", padding="10")
        input_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Target
        ttk.Label(input_frame, text="Target IP/Hostname:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.target_entry = ttk.Entry(input_frame, width=30)
        self.target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=5)
        self.target_entry.insert(0, "127.0.0.1")
        
        # Port Range
        ttk.Label(input_frame, text="Start Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.start_port = ttk.Entry(input_frame, width=10)
        self.start_port.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        self.start_port.insert(0, "1")
        
        ttk.Label(input_frame, text="End Port:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.end_port = ttk.Entry(input_frame, width=10)
        self.end_port.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        self.end_port.insert(0, "1024")
        
        # Quick scan buttons
        quick_frame = ttk.Frame(input_frame)
        quick_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(quick_frame, text="Common (1-1024)", 
                  command=lambda: self.set_port_range("1", "1024")).pack(side=tk.LEFT, padx=5)
        ttk.Button(quick_frame, text="Web Ports", 
                  command=lambda: self.set_port_range("80", "8080")).pack(side=tk.LEFT, padx=5)
        ttk.Button(quick_frame, text="Database Ports", 
                  command=lambda: self.set_port_range("3306", "5432")).pack(side=tk.LEFT, padx=5)
        ttk.Button(quick_frame, text="Mail Ports", 
                  command=lambda: self.set_port_range("25", "995")).pack(side=tk.LEFT, padx=5)
        ttk.Button(quick_frame, text="Full Range (1-65535)", 
                  command=lambda: self.set_port_range("1", "65535")).pack(side=tk.LEFT, padx=5)
        
        # Scan options
        options_frame = ttk.LabelFrame(main_container, text="Scan Options", padding="10")
        options_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(options_frame, text="Timeout (seconds):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.timeout_entry = ttk.Entry(options_frame, width=10)
        self.timeout_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.timeout_entry.insert(0, "1.0")
        
        ttk.Label(options_frame, text="Max Threads:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.threads_entry = ttk.Entry(options_frame, width=10)
        self.threads_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        self.threads_entry.insert(0, "100")
        
        # Accuracy tips
        accuracy_label = ttk.Label(options_frame, 
                                   text="💡 Tip: Increase timeout for better accuracy on firewalled networks | Lower threads for stability",
                                   foreground="gray")
        accuracy_label.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Control buttons
        button_frame = ttk.Frame(main_container)
        button_frame.grid(row=3, column=0, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        self.save_button = ttk.Button(button_frame, text="Save Results", command=self.save_results, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        # Progress frame
        progress_frame = ttk.LabelFrame(main_container, text="Scan Progress", padding="10")
        progress_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        self.status_label = ttk.Label(progress_frame, text="Ready")
        self.status_label.pack()
        
        # Stats frame
        stats_frame = ttk.Frame(progress_frame)
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.time_label = ttk.Label(stats_frame, text="Elapsed: 0.00s")
        self.time_label.pack(side=tk.LEFT, padx=10)
        
        self.speed_label = ttk.Label(stats_frame, text="Speed: 0 ports/s")
        self.speed_label.pack(side=tk.LEFT, padx=10)
        
        # Results frame - FIXED SCROLLING
        results_frame = ttk.LabelFrame(main_container, text="Scan Results", padding="10")
        results_frame.grid(row=5, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Create a container frame for treeview and scrollbar
        tree_container = ttk.Frame(results_frame)
        tree_container.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview
        self.tree = ttk.Treeview(tree_container, columns=('Port', 'Service', 'Status'), 
                                show='headings', height=15)
        self.tree.heading('Port', text='Port Number')
        self.tree.heading('Service', text='Service Name')
        self.tree.heading('Status', text='Status')
        self.tree.column('Port', width=100, anchor='center')
        self.tree.column('Service', width=200, anchor='w')
        self.tree.column('Status', width=100, anchor='center')
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack correctly - scrollbar on right, tree on left
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Bind mouse wheel for scrolling
        self.tree.bind("<MouseWheel>", self._on_mousewheel)
        
        # Status bar
        self.status_bar = ttk.Label(self, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling"""
        self.tree.yview_scroll(int(-1*(event.delta/120)), "units")
        
    def set_port_range(self, start, end):
        """Set port range from quick buttons"""
        self.start_port.delete(0, tk.END)
        self.start_port.insert(0, start)
        self.end_port.delete(0, tk.END)
        self.end_port.insert(0, end)
        
    def start_scan(self):
        """Start the port scan"""
        # Validate inputs
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or hostname")
            return
            
        try:
            start = int(self.start_port.get())
            end = int(self.end_port.get())
            timeout = float(self.timeout_entry.get())
            threads = int(self.threads_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numbers for ports, timeout, and threads")
            return
            
        if start < 1 or end > 65535 or start > end:
            messagebox.showerror("Error", "Port range must be between 1-65535 and start <= end")
            return
            
        if timeout <= 0:
            messagebox.showerror("Error", "Timeout must be greater than 0")
            return
            
        if threads < 1 or threads > 500:
            messagebox.showerror("Error", "Threads must be between 1 and 500")
            return
            
        # Clear previous results
        self.clear_results()
        
        # Create scanner
        self.scanner = PortScanner(target, start, end, timeout, threads)
        self.is_scanning = True
        
        # Update UI
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)
        self.progress_bar['maximum'] = self.scanner.total_ports
        self.progress_bar['value'] = 0
        
        port_info = f"{start}-{end}"
        self.status_bar.config(text=f"Starting scan of {target} (ports {port_info})...")
        
        # Start scan in separate thread
        self.scanner_thread = threading.Thread(target=self.scan_worker, daemon=True)
        self.scanner_thread.start()
        
        # Start polling for results
        self.poll_results()
        self.update_elapsed_time()
        
    def scan_worker(self):
        """Worker function for scanning"""
        try:
            self.scanner.run()
        except Exception as e:
            self.scanner.result_queue.put(('error', str(e), None))
            self.scanner.result_queue.put(('done', None, None))
        
    def poll_results(self):
        """Poll for results from scanner"""
        if not self.is_scanning:
            return
            
        try:
            # Process all pending results
            while True:
                msg_type, value1, value2 = self.scanner.result_queue.get_nowait()
                
                if msg_type == 'open':
                    port, service = value1, value2
                    self.tree.insert('', 'end', values=(port, service, 'OPEN'), tags=('open',))
                    
                elif msg_type == 'progress':
                    scanned, total = value1, value2
                    self.progress_bar['value'] = scanned
                    percent = (scanned / total) * 100 if total > 0 else 0
                    self.status_label.config(text=f"Scanning... {scanned}/{total} ports ({percent:.1f}%)")
                    
                    # Update speed if available
                    if self.scanner and self.scanner.scan_speed > 0:
                        self.speed_label.config(text=f"Speed: {self.scanner.scan_speed:.1f} ports/s")
                    
                elif msg_type == 'error':
                    self.status_bar.config(text=f"Error: {value1}")
                    messagebox.showerror("Scan Error", value1)
                    self.stop_scan()
                    
                elif msg_type == 'done':
                    self.scan_complete()
                    
        except queue.Empty:
            pass
            
        # Schedule next poll if still scanning
        if self.is_scanning:
            self.after(100, self.poll_results)
            
    def scan_complete(self):
        """Handle scan completion"""
        self.is_scanning = False
        stats = self.scanner.get_scan_stats()
        
        # Configure tree tags for coloring
        self.tree.tag_configure('open', foreground='green')
        
        status_text = f"Scan complete! Found {stats['open']} open ports"
        if stats['filtered'] > 0:
            status_text += f" | {stats['filtered']} filtered ports (timeout)"
        
        self.status_label.config(text=status_text)
        self.status_bar.config(text=status_text)
        
        # Update stats display
        self.speed_label.config(text=f"Avg Speed: {stats['speed']:.1f} ports/s")
        
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        if stats['open'] > 0:
            self.save_button.config(state=tk.NORMAL)
            
        # Show summary message
        messagebox.showinfo("Scan Complete", 
                           f"Scan Results Summary:\n\n"
                           f"Total ports scanned: {stats['total']}\n"
                           f"Open ports: {stats['open']}\n"
                           f"Closed ports: {stats['closed']}\n"
                           f"Filtered ports: {stats['filtered']}\n"
                           f"Duration: {stats['duration']:.2f} seconds\n"
                           f"Average speed: {stats['speed']:.1f} ports/second")
            
    def update_elapsed_time(self):
        """Update elapsed time display"""
        if self.is_scanning and self.scanner:
            elapsed = self.scanner.get_scan_duration()
            self.time_label.config(text=f"Elapsed: {elapsed:.2f}s")
            self.elapsed_time_id = self.after(200, self.update_elapsed_time)
        elif not self.is_scanning and self.elapsed_time_id:
            if self.elapsed_time_id:
                self.after_cancel(self.elapsed_time_id)
                self.elapsed_time_id = None
                
    def stop_scan(self):
        """Stop the ongoing scan"""
        if self.scanner:
            self.scanner.stop()
            self.is_scanning = False
            self.status_label.config(text="Scan stopped by user")
            self.status_bar.config(text="Scan stopped by user")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            
    def clear_results(self):
        """Clear all results"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.progress_bar['value'] = 0
        self.status_label.config(text="Ready")
        self.time_label.config(text="Elapsed: 0.00s")
        self.speed_label.config(text="Speed: 0 ports/s")
        self.save_button.config(state=tk.DISABLED)
        if not self.is_scanning:
            self.status_bar.config(text="Ready")
            
    def save_results(self):
        """Save results to file"""
        if not self.scanner or not self.scanner.open_ports:
            messagebox.showinfo("Info", "No results to save")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        if filename:
            try:
                stats = self.scanner.get_scan_stats()
                
                with open(filename, 'w') as f:
                    if filename.endswith('.csv'):
                        # CSV format
                        f.write("Port,Service,ResponseTime(ms)\n")
                        for port, service, elapsed in self.scanner.get_open_ports_sorted():
                            f.write(f"{port},{service},{elapsed*1000:.2f}\n")
                    else:
                        # Text format
                        f.write("Network Port Scan Results\n")
                        f.write("="*60 + "\n")
                        f.write(f"Target: {self.scanner.target}\n")
                        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Port Range: {self.scanner.start_port}-{self.scanner.end_port}\n")
                        f.write(f"Scan Duration: {stats['duration']:.2f} seconds\n")
                        f.write(f"Average Speed: {stats['speed']:.1f} ports/second\n")
                        f.write(f"Open Ports Found: {stats['open']}\n")
                        f.write(f"Filtered Ports: {stats['filtered']}\n")
                        f.write("="*60 + "\n\n")
                        f.write("Open Ports:\n")
                        f.write("-"*40 + "\n")
                        f.write(f"{'Port':<8} {'Service':<20} {'Response':<12}\n")
                        f.write("-"*40 + "\n")
                        
                        for port, service, elapsed in self.scanner.get_open_ports_sorted():
                            f.write(f"{port:<8} {service:<20} {elapsed*1000:.2f}ms\n")
                            
                        if stats['filtered'] > 0:
                            f.write(f"\nNote: {stats['filtered']} ports were filtered/timeout and not included in results.\n")
                            f.write("Consider increasing timeout for better accuracy on firewalled networks.\n")
                            
                messagebox.showinfo("Success", f"Results saved to:\n{filename}")
                self.status_bar.config(text=f"Results saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save file:\n{str(e)}")
                
    def on_closing(self):
        """Handle window closing"""
        if self.is_scanning:
            if messagebox.askokcancel("Quit", "Scan in progress. Are you sure you want to quit?"):
                self.stop_scan()
                self.destroy()
        else:
            self.destroy()

# ---------------------------
# Main Entry Point
# ---------------------------
def main():
    try:
        app = Network_Port_Scanner_GUI()
        app.protocol("WM_DELETE_WINDOW", app.on_closing)
        app.mainloop()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
