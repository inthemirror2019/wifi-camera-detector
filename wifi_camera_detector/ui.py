# UI interface module
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import webbrowser
from datetime import datetime


class CameraDetectorUI:
    """Camera Detector UI"""

    def __init__(self, root, scanner, detector):
        self.root = root
        self.scanner = scanner
        self.detector = detector
        self.scan_thread = None
        self.detection_thread = None
        self.scanning = False
        self.detected_devices = []

        self.setup_ui()

    def setup_ui(self):
        """Setup UI interface"""
        self.root.title("WiFi Camera Detector - Anti-spy Detection")
        self.root.geometry("1000x700")
        self.root.minsize(900, 600)

        # Center window
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - 1000) // 2
        y = (screen_height - 700) // 2
        self.root.geometry(f"1000x700+{x}+{y}")

        # Set styles
        self.setup_styles()

        # Create main frame
        self.create_main_frame()

        # Create status bar
        self.create_status_bar()

    def setup_styles(self):
        """Setup styles"""
        style = ttk.Style()

        # Define colors
        self.colors = {
            'primary': '#2196F3',      # Blue
            'success': '#4CAF50',      # Green
            'warning': '#FF9800',      # Orange
            'danger': '#F44336',       # Red
            'info': '#00BCD4',         # Cyan
            'bg': '#FAFAFA',           # Background
            'card': '#FFFFFF',         # Card
            'text': '#212121',         # Text
            'text_secondary': '#757575' # Secondary text
        }

        # Configure styles
        style.configure('Title.TLabel', font=('Microsoft YaHei', 18, 'bold'))
        style.configure('Subtitle.TLabel', font=('Microsoft YaHei', 12), foreground=self.colors['text_secondary'])
        style.configure('Card.TFrame', background=self.colors['card'])
        style.configure('Info.TLabel', font=('Microsoft YaHei', 10))
        style.configure('Status.TLabel', font=('Microsoft YaHei', 9), foreground=self.colors['text_secondary'])

        # Button styles
        style.configure('Primary.TButton', font=('Microsoft YaHei', 11, 'bold'))
        style.configure('Secondary.TButton', font=('Microsoft YaHei', 10))

        # Treeview styles
        style.configure('Custom.Treeview', font=('Microsoft YaHei', 10), rowheight=30)
        style.configure('Custom.Treeview.Heading', font=('Microsoft YaHei', 10, 'bold'))

    def create_main_frame(self):
        """Create main frame"""
        # Main container
        main_container = ttk.Frame(self.root, padding="20")
        main_container.pack(fill=tk.BOTH, expand=True)

        # Header area
        header_frame = ttk.Frame(main_container)
        header_frame.pack(fill=tk.X, pady=(0, 20))

        # Icon (using Unicode character)
        icon_label = ttk.Label(header_frame, text="📹", font=('Arial', 32))
        icon_label.pack(side=tk.LEFT, padx=(0, 15))

        # Title and subtitle
        title_frame = ttk.Frame(header_frame)
        title_frame.pack(side=tk.LEFT)

        title = ttk.Label(title_frame, text="WiFi Camera Detector", style='Title.TLabel')
        title.pack(anchor=tk.W)

        subtitle = ttk.Label(title_frame, text="Detect suspicious camera devices in LAN, prevent spying", style='Subtitle.TLabel')
        subtitle.pack(anchor=tk.W)

        # Scan control area
        control_frame = ttk.LabelFrame(main_container, text="Scan Control", padding="15")
        control_frame.pack(fill=tk.X, pady=(0, 15))

        # Network info and scan button
        info_frame = ttk.Frame(control_frame)
        info_frame.pack(fill=tk.X)

        # Network info
        self.network_info = ttk.Label(info_frame, text=f"Local IP: {self.scanner.local_ip} | Scan Network: {self.scanner.network}",
                                      font=('Microsoft YaHei', 10), foreground=self.colors['text_secondary'])
        self.network_info.pack(side=tk.LEFT)

        # Scan button
        self.scan_btn = tk.Button(info_frame, text="🔍 Start Scan", font=('Microsoft YaHei', 11, 'bold'),
                                  bg=self.colors['primary'], fg='white', activebackground='#1976D2',
                                  activeforeground='white', padx=20, pady=8, cursor='hand2',
                                  relief=tk.FLAT, command=self.start_scan)
        self.scan_btn.pack(side=tk.RIGHT)

        # Progress bar area
        progress_frame = ttk.Frame(control_frame)
        progress_frame.pack(fill=tk.X, pady=(15, 0))

        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var,
                                              maximum=100, length=100, mode='determinate')
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.progress_label = ttk.Label(progress_frame, text="0%", font=('Microsoft YaHei', 10),
                                        width=6)
        self.progress_label.pack(side=tk.RIGHT, padx=(10, 0))

        # Status text
        self.status_label = ttk.Label(control_frame, text="Ready, click 'Start Scan' to begin detection",
                                      font=('Microsoft YaHei', 9), foreground=self.colors['text_secondary'])
        self.status_label.pack(anchor=tk.W, pady=(10, 0))

        # Result list area
        result_frame = ttk.LabelFrame(main_container, text="Scan Results", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True)

        # Result table
        columns = ('ip', 'mac', 'vendor', 'ports', 'camera', 'risk')
        self.tree = ttk.Treeview(result_frame, columns=columns, show='headings',
                                 style='Custom.Treeview', height=10)

        # Define columns
        self.tree.heading('ip', text='IP Address')
        self.tree.heading('mac', text='MAC Address')
        self.tree.heading('vendor', text='Vendor')
        self.tree.heading('ports', text='Open Ports')
        self.tree.heading('camera', text='Camera')
        self.tree.heading('risk', text='Risk Level')

        # Set column width
        self.tree.column('ip', width=120, anchor='center')
        self.tree.column('mac', width=140, anchor='center')
        self.tree.column('vendor', width=150, anchor='center')
        self.tree.column('ports', width=120, anchor='center')
        self.tree.column('camera', width=80, anchor='center')
        self.tree.column('risk', width=100, anchor='center')

        # Scrollbar
        scrollbar_y = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(result_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        # Layout
        self.tree.grid(row=0, column=0, sticky='nsew')
        scrollbar_y.grid(row=0, column=1, sticky='ns')
        scrollbar_x.grid(row=1, column=0, sticky='ew')

        result_frame.grid_rowconfigure(0, weight=1)
        result_frame.grid_columnconfigure(0, weight=1)

        # Bottom buttons
        btn_frame = ttk.Frame(main_container)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        self.export_btn = tk.Button(btn_frame, text="📥 Export", font=('Microsoft YaHei', 9),
                                    bg=self.colors['info'], fg='white',
                                    activebackground='#0097A7', padx=12, pady=3,
                                    relief=tk.FLAT, cursor='hand2',
                                    command=self.export_results)
        self.export_btn.pack(side=tk.LEFT)

        self.clear_btn = tk.Button(btn_frame, text="🗑️ Clear", font=('Microsoft YaHei', 9),
                                   bg=self.colors['text_secondary'], fg='white',
                                   activebackground='#616161', padx=12, pady=3,
                                   relief=tk.FLAT, cursor='hand2',
                                   command=self.clear_results)
        self.clear_btn.pack(side=tk.LEFT, padx=(10, 0))

        self.about_btn = tk.Button(btn_frame, text="❓ About", font=('Microsoft YaHei', 9),
                                   bg=self.colors['card'], fg=self.colors['text'],
                                   activebackground='#E0E0E0', padx=12, pady=3,
                                   relief=tk.FLAT, cursor='hand2',
                                   command=self.show_about)
        self.about_btn.pack(side=tk.RIGHT)

    def create_status_bar(self):
        """Create status bar"""
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W,
                                    font=('Microsoft YaHei', 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def start_scan(self):
        """Start scan"""
        if self.scanning:
            self.stop_scan()
            return

        # Clear previous results
        self.clear_results()

        # Update UI state
        self.scanning = True
        self.scan_btn.config(text="⏹️ Stop Scan", bg=self.colors['danger'])
        self.status_label.config(text="Scanning network devices...", foreground=self.colors['primary'])
        self.progress_var.set(0)
        self.progress_label.config(text="0%")

        # Execute scan in background thread
        self.scan_thread = threading.Thread(target=self._scan_worker)
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def stop_scan(self):
        """Stop scan"""
        self.scanning = False
        self.scanner.stop()
        self.detector.stop()
        self.status_label.config(text="Scan stopped", foreground=self.colors['warning'])
        self.scan_btn.config(text="🔍 Start Scan", bg=self.colors['primary'])

    def _scan_worker(self):
        """Scan worker thread"""
        try:
            # Phase 1: Device discovery
            self.root.after(0, lambda: self.status_label.config(
                text=f"Scanning devices in network {self.scanner.network}...",
                foreground=self.colors['primary']
            ))

            # Scan network devices
            devices = self.scanner.scan_network(
                progress_callback=self._on_progress,
                result_callback=self._on_device_found
            )

            if not self.scanning:
                return

            # Phase 2: Deep camera detection
            if devices:
                self.root.after(0, lambda: self.status_label.config(
                    text=f"Detecting camera features in {len(devices)} devices...",
                    foreground=self.colors['warning']
                ))

                for i, device in enumerate(devices):
                    if not self.scanning:
                        break

                    # Detect camera
                    result = self.detector.detect_camera(
                        ip=device['ip'],
                        mac=device['mac'],
                        scan_ports=True,
                        check_rtsp=True
                    )

                    if result:
                        self.root.after(0, lambda r=result: self._on_detection_complete(r))

                    # Update progress
                    progress = int((i + 1) / len(devices) * 100)
                    self.root.after(0, lambda p=progress: self.progress_var.set(p))
                    self.root.after(0, lambda p=progress: self.progress_label.config(text=f"{p}%"))

            # Scan complete
            self.root.after(0, self._on_scan_complete)

        except Exception as e:
            self.root.after(0, lambda: self._on_scan_error(str(e)))

    def _on_progress(self, current, total, percent):
        """Progress callback"""
        self.root.after(0, lambda: self.progress_var.set(percent))
        self.root.after(0, lambda: self.progress_label.config(text=f"{percent}%"))
        self.root.after(0, lambda: self.status_label.config(
            text=f"Scanning: {current}/{total} IP addresses...",
            foreground=self.colors['primary']
        ))

    def _on_device_found(self, device):
        """Device found callback"""
        self.root.after(0, lambda: self.status_label.config(
            text=f"Found device: {device['ip']} - {device['mac']}",
            foreground=self.colors['success']
        ))

    def _on_detection_complete(self, result):
        """Detection complete callback"""
        self.detected_devices.append(result)
        self.add_result_to_tree(result)

    def _on_scan_complete(self):
        """Scan complete"""
        self.scanning = False
        camera_count = sum(1 for d in self.detected_devices if d['is_camera'])
        self.scan_btn.config(text="🔍 Start Scan", bg=self.colors['primary'])
        self.status_label.config(
            text=f"Scan complete! Found {len(self.detected_devices)} devices, {camera_count} suspected cameras",
            foreground=self.colors['success']
        )
        self.status_bar.config(text=f"Scan complete | Total: {len(self.detected_devices)} devices | Cameras: {camera_count}")

    def _on_scan_error(self, error_msg):
        """Scan error"""
        self.scanning = False
        self.scan_btn.config(text="🔍 Start Scan", bg=self.colors['primary'])
        self.status_label.config(
            text=f"Scan error: {error_msg}",
            foreground=self.colors['danger']
        )
        messagebox.showerror("Scan Error", f"Error occurred during scan:\n{error_msg}")

    def add_result_to_tree(self, result):
        """Add result to tree"""
        # Determine risk level and color
        risk_level = "Low"
        risk_color = self.colors['success']

        if result.get('is_camera', False):
            if result.get('confidence', 0) > 0.8:
                risk_level = "High"
                risk_color = self.colors['danger']
            elif result.get('confidence', 0) > 0.5:
                risk_level = "Medium"
                risk_color = self.colors['warning']

        # Format data
        ports_str = ", ".join(map(str, result.get('ports', [])))[:30] or "None"
        camera_str = "Yes" if result.get('is_camera', False) else "No"
        vendor = result.get('vendor') or 'Unknown'

        # Insert to tree
        item_id = self.tree.insert('', 'end', values=(
            result.get('ip', 'Unknown'),
            result.get('mac', 'Unknown'),
            vendor[:20],
            ports_str,
            camera_str,
            risk_level
        ), tags=(risk_level,))

        # Set tag color
        self.tree.tag_configure(risk_level, foreground=risk_color)

        # Auto scroll to new item
        self.tree.see(item_id)

    def export_results(self):
        """Export results"""
        if not self.detected_devices:
            messagebox.showwarning("No Data", "No scan results to export")
            return

        try:
            from datetime import datetime
            import json

            filename = f"camera_detection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.detected_devices, f, ensure_ascii=False, indent=2)

            messagebox.showinfo("Export Success", f"Results exported to:\n{filename}")

        except Exception as e:
            messagebox.showerror("Export Failed", f"Export error:\n{str(e)}")

    def clear_results(self):
        """Clear results"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.detected_devices.clear()
        self.status_bar.config(text="Ready")

    def show_about(self):
        """Show about dialog"""
        about_text = """
WiFi Camera Detector v1.0

A tool to detect suspicious camera devices in your local network.

Features:
- Network device scanning
- Camera feature detection
- Risk level assessment
- RTSP stream detection

Warning: This tool is for security testing only.
Do not use on networks you don't have permission to scan.
        """
        messagebox.showinfo("About", about_text)
