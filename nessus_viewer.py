import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set


class NessusViewer(tk.Tk):
    """Tkinter GUI for viewing one or more Nessus (.nessus) files.

    The interface presents a list of discovered issues. Double clicking an issue
    displays full details. Opened Nessus files and a comma-separated list of
    unique open TCP/UDP ports are available in a separate tab.
    """

    def __init__(self) -> None:
        super().__init__()
        self.title("Nessus Viewer")
        self.geometry("1000x600")

        self.issues: List[Dict[str, str]] = []
        self.visible_issues: List[Dict[str, str]] = []
        self.ports: Set[int] = set()
        self.opened_files: List[str] = []

        self._create_widgets()

    def _create_widgets(self) -> None:
        """Create and lay out widgets."""
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True)

        records_frame = ttk.Frame(notebook)
        notebook.add(records_frame, text="Records")

        list_frame = ttk.Frame(records_frame)
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        search_frame = ttk.Frame(list_frame)
        search_frame.pack(fill=tk.X)

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        search_entry.bind("<KeyRelease>", self.filter_issues)
        ttk.Button(search_frame, text="Clear", command=self.clear_filter).pack(
            side=tk.LEFT, padx=5
        )

        self.issue_list = tk.Listbox(list_frame)
        self.issue_list.pack(fill=tk.BOTH, expand=True)
        self.issue_list.bind("<Double-Button-1>", self.show_details)

        detail_frame = ttk.Frame(records_frame)
        detail_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.detail_text = tk.Text(detail_frame, wrap="word")
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        info_frame = ttk.Frame(notebook)
        notebook.add(info_frame, text="Files & Ports")

        ttk.Label(info_frame, text="Opened Nessus Files:").pack(
            anchor=tk.W, padx=5, pady=(5, 0)
        )
        self.file_checkbox_frame = ttk.Frame(info_frame)
        self.file_checkbox_frame.pack(fill=tk.X, padx=5, pady=5)
        self.file_vars: Dict[str, tk.BooleanVar] = {}

        ttk.Label(info_frame, text="Open Ports:").pack(anchor=tk.W, padx=5)
        self.port_text = tk.Text(info_frame, height=5, wrap="word")
        self.port_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))
        self.port_text.config(state=tk.DISABLED)

        self.copy_button = ttk.Button(
            info_frame, text="Copy Ports", command=self.copy_ports
        )
        self.copy_button.pack(anchor=tk.W, padx=5, pady=(0, 5))

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
        self.visible_issues.clear()
        self.ports.clear()
        self.issue_list.delete(0, tk.END)
        self.detail_text.delete("1.0", tk.END)

        self.opened_files = [os.path.basename(p) for p in file_paths]

        for child in self.file_checkbox_frame.winfo_children():
            child.destroy()
        self.file_vars.clear()
        for name in self.opened_files:
            var = tk.BooleanVar(value=True)
            cb = ttk.Checkbutton(
                self.file_checkbox_frame,
                text=name,
                variable=var,
                command=self.filter_issues,
            )
            cb.pack(anchor=tk.W)
            self.file_vars[name] = var

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
                    issue["file"] = os.path.basename(path)
                    self.issues.append(issue)

        self.filter_issues()

    def _refresh_issue_list(self) -> None:
        """Refresh the listbox with the current visible issues."""
        self.issue_list.delete(0, tk.END)
        for issue in self.visible_issues:
            display = (
                f"{issue['host']}:{issue['port']}/{issue['protocol']} - "
                f"{issue['plugin_name']} (Severity {issue['severity']})"
            )
            self.issue_list.insert(tk.END, display)

    def filter_issues(self, _event: Optional[tk.Event] = None) -> None:
        """Filter issues based on the search entry and selected files."""
        term = self.search_var.get().lower()
        selected_files = [name for name, var in self.file_vars.items() if var.get()]

        filtered = [
            issue
            for issue in self.issues
            if (not selected_files or issue.get("file", "") in selected_files)
        ]
        if term:
            filtered = [
                issue
                for issue in filtered
                if term in issue["host"].lower()
                or term in issue["protocol"].lower()
                or term in issue["severity"].lower()
                or term in issue["plugin_name"].lower()
                or term in str(issue["port"])
                or term in issue.get("file", "").lower()
            ]

        self.visible_issues = filtered
        self._refresh_issue_list()

        self.ports = {
            issue["port"]
            for issue in self.issues
            if issue["port"]
            and (not selected_files or issue.get("file", "") in selected_files)
        }
        self.port_text.config(state=tk.NORMAL)
        self.port_text.delete("1.0", tk.END)
        if self.ports:
            ports_sorted = ",".join(str(p) for p in sorted(self.ports))
            self.port_text.insert(tk.END, ports_sorted)
        else:
            self.port_text.insert(tk.END, "None")
        self.port_text.config(state=tk.DISABLED)

    def clear_filter(self) -> None:
        """Clear the search filter and show all issues."""
        self.search_var.set("")
        self.filter_issues()

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
        issue = self.visible_issues[selection[0]]
        details = (
            f"Host: {issue['host']}\n"
            f"Port: {issue['port']}/{issue['protocol']}\n"
            f"Severity: {issue['severity']}\n"
            f"Plugin ID: {issue['plugin_id']}\n"
            f"Plugin Name: {issue['plugin_name']}\n"
            f"Source File: {issue.get('file', '')}\n\n"
            f"Description:\n{issue['description']}\n\n"
            f"Solution:\n{issue['solution']}\n"
        )
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, details)


if __name__ == "__main__":
    app = NessusViewer()
    app.mainloop()
