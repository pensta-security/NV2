import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List, Optional, Set


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

        # Each issue dictionary may contain strings or lists depending on the
        # data extracted from the Nessus file.  Use ``Any`` for the value type
        # to accommodate list fields such as CVEs or other references.
        self.issues: List[Dict[str, Any]] = []
        self.visible_issues: List[Dict[str, Any]] = []
        self.ports: Set[int] = set()
        self.opened_files: List[str] = []
        self.recent_files: List[str] = []
        self.recent_files_path = os.path.join(
            os.path.expanduser("~"), ".nessus_viewer_recent"
        )
        self._load_recent_files()

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

        # Text widget for long-form information such as descriptions and
        # plugin output.
        self.detail_text = tk.Text(detail_frame, wrap="word")
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        # Table for references like CVE/BID/XREF that are easier to view in a
        # structured format.
        self.ref_tree = ttk.Treeview(
            detail_frame, columns=("type", "value"), show="headings", height=5
        )
        self.ref_tree.heading("type", text="Type")
        self.ref_tree.heading("value", text="Value")
        self.ref_tree.pack(fill=tk.BOTH, expand=True)

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
        self.recent_menu = tk.Menu(file_menu, tearoff=0)
        file_menu.add_cascade(label="Recent Files", menu=self.recent_menu)
        self._update_recent_files_menu()
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)

    def open_files(self) -> None:
        """Open and parse one or more Nessus files."""
        file_paths = filedialog.askopenfilenames(
            title="Open Nessus files",
            filetypes=[("Nessus files", "*.nessus"), ("All files", "*.*")],
        )
        if file_paths:
            self._load_files(file_paths)

    def open_recent_file(self, path: str) -> None:
        """Import a Nessus file from the recent files list."""
        if not os.path.exists(path):
            messagebox.showerror("File not found", f"{path} not found")
            if path in self.recent_files:
                self.recent_files.remove(path)
                self._save_recent_files()
                self._update_recent_files_menu()
            return
        self._import_files([path])

    def _load_files(self, file_paths: Iterable[str]) -> None:
        """Replace current data with the given Nessus files."""
        self._clear_data()
        self._import_files(file_paths)

    def _clear_data(self) -> None:
        """Remove all currently loaded issues and related state."""
        self.issues.clear()
        self.visible_issues.clear()
        self.ports.clear()
        self.issue_list.delete(0, tk.END)
        self.detail_text.delete("1.0", tk.END)
        self.opened_files = []
        for child in self.file_checkbox_frame.winfo_children():
            child.destroy()
        self.file_vars.clear()

    def _import_files(self, file_paths: Iterable[str]) -> None:
        """Parse Nessus files and append to current state."""
        file_paths = list(file_paths)
        for path in file_paths:
            name = os.path.basename(path)
            if name in self.opened_files:
                continue
            self.opened_files.append(name)
            var = tk.BooleanVar(value=True)
            cb = ttk.Checkbutton(
                self.file_checkbox_frame, text=name, variable=var, command=self.filter_issues
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

        for path in file_paths:
            if path in self.recent_files:
                self.recent_files.remove(path)
            self.recent_files.insert(0, path)
        self.recent_files = self.recent_files[:10]
        self._save_recent_files()
        self._update_recent_files_menu()

    def _update_recent_files_menu(self) -> None:
        """Refresh the Recent Files submenu."""
        self.recent_menu.delete(0, tk.END)
        if not self.recent_files:
            self.recent_menu.add_command(label="(No recent files)", state=tk.DISABLED)
            return
        for path in self.recent_files:
            self.recent_menu.add_command(
                label=os.path.basename(path),
                command=lambda p=path: self.open_recent_file(p),
            )

    def _load_recent_files(self) -> None:
        """Load recent files list from disk."""
        try:
            with open(self.recent_files_path, "r", encoding="utf-8") as fh:
                self.recent_files = [line.strip() for line in fh if line.strip()]
        except OSError:
            self.recent_files = []

    def _save_recent_files(self) -> None:
        """Persist recent files list to disk."""
        try:
            with open(self.recent_files_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(self.recent_files))
        except OSError:
            pass

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

    def _parse_report_item(self, item: ET.Element, host: str) -> Dict[str, Any]:
        """Extract relevant information from a ReportItem."""
        port_str = item.get("port", "0")
        port = int(port_str) if port_str.isdigit() else 0

        # Collect multi-valued elements.  ``findall`` returns an empty list if
        # the tag does not exist which satisfies the requirement that missing
        # data is handled gracefully.
        cve_list = [e.text for e in item.findall("cve") if e.text]
        bid_list = [e.text for e in item.findall("bid") if e.text]
        xref_list = [e.text for e in item.findall("xref") if e.text]

        return {
            "host": host,
            "port": port,
            "protocol": item.get("protocol", ""),
            "severity": item.get("severity", ""),
            "plugin_id": item.get("pluginID", ""),
            "plugin_name": item.get("pluginName", ""),
            "description": item.findtext("description", default=""),
            "solution": item.findtext("solution", default=""),
            "plugin_output": item.findtext("plugin_output", default=""),
            "risk_factor": item.findtext("risk_factor", default=""),
            "cve": cve_list,
            "bid": bid_list,
            "xref": xref_list,
        }

    def show_details(self, _event: tk.Event) -> None:
        """Display details of the selected issue."""
        selection = self.issue_list.curselection()
        if not selection:
            return
        issue = self.visible_issues[selection[0]]

        # Build the textual portion of the details view.
        details = [
            f"Host: {issue['host']}",
            f"Port: {issue['port']}/{issue['protocol']}",
            f"Severity: {issue['severity']}",
            f"Risk Factor: {issue.get('risk_factor', '')}",
            f"Plugin ID: {issue['plugin_id']}",
            f"Plugin Name: {issue['plugin_name']}",
            f"Source File: {issue.get('file', '')}",
            "",
            f"Description:\n{issue['description']}",
        ]

        if issue.get("solution"):
            details.append(f"\nSolution:\n{issue['solution']}")
        if issue.get("plugin_output"):
            details.append(f"\nPlugin Output:\n{issue['plugin_output']}")

        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, "\n".join(details))

        # Populate the reference table.
        for row in self.ref_tree.get_children():
            self.ref_tree.delete(row)
        for ref in issue.get("cve", []):
            self.ref_tree.insert("", tk.END, values=("CVE", ref))
        for ref in issue.get("bid", []):
            self.ref_tree.insert("", tk.END, values=("BID", ref))
        for ref in issue.get("xref", []):
            self.ref_tree.insert("", tk.END, values=("XREF", ref))


if __name__ == "__main__":
    app = NessusViewer()
    app.mainloop()
