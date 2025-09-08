import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import xml.etree.ElementTree as ET
from typing import List, Dict, Set


class NessusViewer(tk.Tk):
    """Tkinter GUI for viewing one or more Nessus (.nessus) files.

    The interface presents a list of discovered issues. Double clicking an issue
    displays full details. A comma-separated list of unique open TCP/UDP ports is
    shown at the bottom of the window.
    """

    def __init__(self) -> None:
        super().__init__()
        self.title("Nessus Viewer")
        self.geometry("1000x600")

        self.issues: List[Dict[str, str]] = []
        self.ports: Set[int] = set()

        self._create_widgets()

    def _create_widgets(self) -> None:
        """Create and lay out widgets."""
        top_frame = ttk.Frame(self)
        top_frame.pack(fill=tk.BOTH, expand=True)

        list_frame = ttk.Frame(top_frame)
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.issue_list = tk.Listbox(list_frame)
        self.issue_list.pack(fill=tk.BOTH, expand=True)
        self.issue_list.bind("<Double-Button-1>", self.show_details)

        detail_frame = ttk.Frame(top_frame)
        detail_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.detail_text = tk.Text(detail_frame, wrap="word")
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        bottom_frame = ttk.Frame(self)
        bottom_frame.pack(fill=tk.X)

        self.port_label = ttk.Label(bottom_frame, text="Ports: ")
        self.port_label.pack(side=tk.LEFT, padx=5)

        self.copy_button = ttk.Button(
            bottom_frame, text="Copy Ports", command=self.copy_ports
        )
        self.copy_button.pack(side=tk.LEFT, padx=5)

        menu = tk.Menu(self)
        self.config(menu=menu)
        file_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open Nessus Files", command=self.open_files)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)

    def open_files(self) -> None:
        """Open and parse one or more Nessus files."""
        file_paths = filedialog.askopenfilenames(
            title="Open Nessus files",
            filetypes=[("Nessus files", "*.nessus"), ("All files", "*.*")],
        )
        if not file_paths:
            return

        self.issues.clear()
        self.ports.clear()
        self.issue_list.delete(0, tk.END)
        self.detail_text.delete("1.0", tk.END)

        for path in file_paths:
            try:
                tree = ET.parse(path)
            except ET.ParseError as exc:
                messagebox.showerror("Parse error", f"Failed to parse {path}: {exc}")
                continue

            root = tree.getroot()
            for report_host in root.findall(".//ReportHost"):
                host = report_host.get("name", "")
                for report_item in report_host.findall("ReportItem"):
                    issue = self._parse_report_item(report_item, host)
                    self.issues.append(issue)
                    display = (
                        f"{issue['host']}:{issue['port']}/{issue['protocol']} - "
                        f"{issue['plugin_name']} (Severity {issue['severity']})"
                    )
                    self.issue_list.insert(tk.END, display)

                    port = issue["port"]
                    if port:
                        self.ports.add(port)

        if self.ports:
            ports_sorted = ",".join(str(p) for p in sorted(self.ports))
            self.port_label.config(text=f"Ports: {ports_sorted}")
        else:
            self.port_label.config(text="Ports: None")

    def copy_ports(self) -> None:
        """Copy the comma-separated list of open ports to the clipboard."""
        if not self.ports:
            messagebox.showwarning("No Ports", "No open ports to copy.")
            return
        ports_sorted = ",".join(str(p) for p in sorted(self.ports))
        self.clipboard_clear()
        self.clipboard_append(ports_sorted)
        messagebox.showinfo("Copied", "Open ports copied to clipboard.")

    def _parse_report_item(self, item: ET.Element, host: str) -> Dict[str, str]:
        """Extract relevant information from a ReportItem."""
        port_str = item.get("port", "0")
        port = int(port_str) if port_str.isdigit() else 0
        return {
            "host": host,
            "port": port,
            "protocol": item.get("protocol", ""),
            "severity": item.get("severity", ""),
            "plugin_id": item.get("pluginID", ""),
            "plugin_name": item.get("pluginName", ""),
            "description": item.findtext("description", default=""),
            "solution": item.findtext("solution", default=""),
        }

    def show_details(self, _event: tk.Event) -> None:
        """Display details of the selected issue."""
        selection = self.issue_list.curselection()
        if not selection:
            return
        issue = self.issues[selection[0]]
        details = (
            f"Host: {issue['host']}\n"
            f"Port: {issue['port']}/{issue['protocol']}\n"
            f"Severity: {issue['severity']}\n"
            f"Plugin ID: {issue['plugin_id']}\n"
            f"Plugin Name: {issue['plugin_name']}\n\n"
            f"Description:\n{issue['description']}\n\n"
            f"Solution:\n{issue['solution']}\n"
        )
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, details)


if __name__ == "__main__":
    app = NessusViewer()
    app.mainloop()
