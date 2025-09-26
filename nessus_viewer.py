import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


# Mapping of numeric severity levels to tag names used for styling rows.
SEVERITY_TAGS = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
}

# Colors chosen for contrast on light and dark themes.
SEVERITY_COLORS = {
    "critical": "#d32f2f",  # red
    "high": "#f57c00",      # orange
    "medium": "#fbc02d",    # yellow
    "low": "#388e3c",       # green
    "info": "#1976d2",      # blue
}

# Human readable names for severity levels used by the filter combobox.
SEVERITY_NAMES = {
    "0": "Info",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Critical",
}
# Map from displayed name back to numeric value.
SEVERITY_NAME_TO_VALUE = {v: k for k, v in SEVERITY_NAMES.items()}
# Options presented in the severity filter including the default.
SEVERITY_FILTER_OPTIONS = ["All severities"] + list(SEVERITY_NAMES.values())

# Default templates available when no saved templates exist on disk.
DEFAULT_SCRIPT_TEMPLATES: Dict[str, str] = {
    "TestSSL": "testssl.sh --ip <host> --port <port>",
}


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
        # Track sort direction for issue columns
        self._sort_reverse: Dict[str, bool] = {}

        # Script builder state stores host/port pairings and reusable templates.
        self.script_entries: List[Tuple[Optional[str], Optional[int]]] = []
        self._script_entry_set: Set[Tuple[Optional[str], Optional[int]]] = set()
        self.script_templates: Dict[str, str] = dict(DEFAULT_SCRIPT_TEMPLATES)

        # Column configuration
        self.columns = ("host", "port", "protocol", "severity", "plugin", "file")
        self.config_path = os.path.join(
            os.path.expanduser("~"), ".nessus_viewer_config.json"
        )
        self.column_widths: Dict[str, int] = {
            "host": 150,
            "port": 70,
            "protocol": 90,
            "severity": 90,
            "plugin": 300,
            "file": 180,
        }

        self._load_recent_files()
        self._load_config()

        self._create_widgets()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

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

        ttk.Label(search_frame, text="Severity:").pack(side=tk.LEFT, padx=5)
        self.severity_var = tk.StringVar(value="All severities")
        severity_combo = ttk.Combobox(
            search_frame,
            textvariable=self.severity_var,
            values=SEVERITY_FILTER_OPTIONS,
            state="readonly",
            width=15,
        )
        severity_combo.pack(side=tk.LEFT, padx=5)
        severity_combo.bind("<<ComboboxSelected>>", self.filter_issues)

        ttk.Button(search_frame, text="Clear", command=self.clear_filter).pack(
            side=tk.LEFT, padx=5
        )

        tree_container = ttk.Frame(list_frame)
        tree_container.pack(fill=tk.BOTH, expand=True)

        tree_vscroll = ttk.Scrollbar(
            tree_container, orient=tk.VERTICAL
        )
        tree_vscroll.pack(side=tk.RIGHT, fill=tk.Y)

        tree_hscroll = ttk.Scrollbar(
            tree_container, orient=tk.HORIZONTAL
        )
        tree_hscroll.pack(side=tk.BOTTOM, fill=tk.X)

        self.issue_tree = ttk.Treeview(
            tree_container,
            columns=self.columns,
            show="headings",
            selectmode="extended",
        )
        self.issue_tree.configure(
            yscrollcommand=tree_vscroll.set, xscrollcommand=tree_hscroll.set
        )
        tree_vscroll.configure(command=self.issue_tree.yview)
        tree_hscroll.configure(command=self.issue_tree.xview)
        headings = {
            "host": "Host",
            "port": "Port",
            "protocol": "Protocol",
            "severity": "Severity",
            "plugin": "Plugin Name",
            "file": "File",
        }
        for col in self.columns:
            self.issue_tree.heading(
                col,
                text=headings[col],
                command=lambda c=col: self.sort_issues(c),
            )
            self.issue_tree.column(
                col,
                stretch=True,
                width=self.column_widths.get(col, 100),
            )
        for tag, color in SEVERITY_COLORS.items():
            self.issue_tree.tag_configure(tag, foreground=color)
        self.issue_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.issue_tree.bind("<<TreeviewSelect>>", self.show_details)
        self.issue_tree.bind(
            "<ButtonRelease-1>", lambda _e: self._capture_column_widths()
        )

        # Context menu for copying selected host/port pairs
        self.issue_menu = tk.Menu(self.issue_tree, tearoff=0)
        self.issue_menu.add_command(
            label="Copy Hosts and Ports", command=self.copy_selected_hosts_ports
        )
        self.issue_menu.add_command(
            label="Send to Script Builder", command=self.send_selected_to_script_builder
        )
        self.issue_tree.bind("<Button-3>", self._show_issue_menu)

        detail_frame = ttk.Frame(records_frame)
        detail_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Text widget for long-form information such as descriptions and
        # plugin output.
        detail_text_container = ttk.Frame(detail_frame)
        detail_text_container.pack(fill=tk.BOTH, expand=True)

        detail_scroll = ttk.Scrollbar(
            detail_text_container, orient=tk.VERTICAL
        )
        detail_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.detail_text = tk.Text(detail_text_container, wrap="word")
        self.detail_text.configure(yscrollcommand=detail_scroll.set)
        self.detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        detail_scroll.configure(command=self.detail_text.yview)

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
        port_text_container = ttk.Frame(info_frame)
        port_text_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))

        port_scroll = ttk.Scrollbar(port_text_container, orient=tk.VERTICAL)
        port_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.port_text = tk.Text(port_text_container, height=5, wrap="word")
        self.port_text.configure(yscrollcommand=port_scroll.set)
        self.port_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        port_scroll.configure(command=self.port_text.yview)
        self.port_text.config(state=tk.DISABLED)

        self.copy_button = ttk.Button(
            info_frame, text="Copy Ports", command=self.copy_ports
        )
        self.copy_button.pack(anchor=tk.W, padx=5, pady=(0, 5))
        self.copy_button.state(["disabled"])

        self.send_ports_button = ttk.Button(
            info_frame,
            text="Send Ports to Script Builder",
            command=self.send_ports_to_script_builder,
        )
        self.send_ports_button.pack(anchor=tk.W, padx=5, pady=(0, 5))
        self.send_ports_button.state(["disabled"])

        script_frame = ttk.Frame(notebook)
        notebook.add(script_frame, text="Script Builder")
        self._build_script_builder_tab(script_frame)

        menu = tk.Menu(self)
        self.config(menu=menu)
        file_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open Nessus Files", command=self.open_files)
        self.recent_menu = tk.Menu(file_menu, tearoff=0)
        file_menu.add_cascade(label="Recent Files", menu=self.recent_menu)
        self._update_recent_files_menu()
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)

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
        self.issue_tree.delete(*self.issue_tree.get_children())
        self._clear_details()
        self.opened_files = []
        for child in self.file_checkbox_frame.winfo_children():
            child.destroy()
        self.file_vars.clear()

    def _clear_details(self) -> None:
        """Reset the detail text and references table."""
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.config(state=tk.DISABLED)
        self.ref_tree.delete(*self.ref_tree.get_children())

    def _import_files(self, file_paths: Iterable[str]) -> None:
        """Parse Nessus files and append to current state."""
        file_paths = list(file_paths)
        new_paths: List[str] = []
        for path in file_paths:
            name = os.path.basename(path)
            if name in self.opened_files:
                # Skip files that have already been imported to avoid
                # duplicate records when selecting a recent file multiple times.
                continue
            self.opened_files.append(name)
            var = tk.BooleanVar(value=True)
            cb = ttk.Checkbutton(
                self.file_checkbox_frame, text=name, variable=var, command=self.filter_issues
            )
            cb.pack(anchor=tk.W)
            self.file_vars[name] = var
            new_paths.append(path)

        if new_paths:
            progress_win = tk.Toplevel(self)
            progress_win.title("Importing files")
            progress_win.transient(self)
            progress_win.grab_set()
            ttk.Label(progress_win, text="Importing Nessus files...").pack(padx=10, pady=10)
            progress = ttk.Progressbar(
                progress_win, length=300, mode="determinate", maximum=len(new_paths)
            )
            progress.pack(padx=10, pady=(0, 10))
            progress_win.update_idletasks()

            try:
                for idx, path in enumerate(new_paths, start=1):
                    try:
                        tree = ET.parse(path)
                    except ET.ParseError as exc:
                        messagebox.showerror(
                            "Parse error", f"Failed to parse {path}: {exc}"
                        )
                        progress["value"] = idx
                        progress_win.update_idletasks()
                        continue

                    root = tree.getroot()
                    for report_host in root.findall(".//ReportHost"):
                        host = report_host.get("name", "")
                        for report_item in report_host.findall("ReportItem"):
                            issue = self._parse_report_item(report_item, host)
                            issue["file"] = os.path.basename(path)
                            self.issues.append(issue)

                    progress["value"] = idx
                    progress_win.update_idletasks()
            finally:
                progress_win.grab_release()
                progress_win.destroy()

        self.filter_issues()

        for path in new_paths:
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

    def _capture_column_widths(self) -> None:
        """Update in-memory column widths from the treeview."""
        for col in self.columns:
            try:
                self.column_widths[col] = self.issue_tree.column(col)["width"]
            except tk.TclError:
                pass

    def _load_config(self) -> None:
        """Load persisted configuration such as column widths."""
        try:
            with open(self.config_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            widths = data.get("column_widths", {})
            for col, width in widths.items():
                if isinstance(width, int):
                    self.column_widths[col] = width

            if "script_templates" in data:
                templates = data.get("script_templates", {})
                if isinstance(templates, dict):
                    loaded_templates: Dict[str, str] = {}
                    for name, template in templates.items():
                        if isinstance(name, str) and isinstance(template, str):
                            loaded_templates[name] = template
                    self.script_templates = loaded_templates
        except (OSError, json.JSONDecodeError):
            pass

    def _save_config(self) -> None:
        """Persist configuration such as column widths to disk."""
        data = {
            "column_widths": self.column_widths,
            "script_templates": self.script_templates,
        }
        try:
            with open(self.config_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
        except OSError:
            pass

    def _on_close(self) -> None:
        """Handle application exit and persist configuration."""
        self._capture_column_widths()
        self._save_config()
        self.destroy()

    def _format_severity(self, severity: Any) -> str:
        """Return a human readable label for a severity value."""
        severity_str = "" if severity is None else str(severity)
        label = SEVERITY_NAMES.get(severity_str)
        if label:
            return f"{label} ({severity_str})"
        return severity_str

    def _refresh_issue_list(self) -> None:
        """Refresh the table with the current visible issues."""
        self.issue_tree.delete(*self.issue_tree.get_children())
        for idx, issue in enumerate(self.visible_issues):
            tag = SEVERITY_TAGS.get(str(issue.get("severity", "")), "")
            severity_display = self._format_severity(issue.get("severity"))
            self.issue_tree.insert(
                "",
                tk.END,
                iid=str(idx),
                tags=(tag,) if tag else (),
                values=(
                    issue["host"],
                    issue["port"],
                    issue["protocol"],
                    severity_display,
                    issue["plugin_name"],
                    issue.get("file", ""),
                ),
            )

        if not self.issue_tree.selection():
            self._clear_details()

    def sort_issues(self, column: str) -> None:
        """Sort the visible issues by the given column."""
        reverse = self._sort_reverse.get(column, False)
        if column in {"port", "severity"}:
            key_func = lambda i: int(i.get(column, 0))
        elif column == "plugin":
            key_func = lambda i: i.get("plugin_name", "").lower()
        else:
            key_func = lambda i: str(i.get(column, "")).lower()
        self.visible_issues.sort(key=key_func, reverse=reverse)
        self._sort_reverse[column] = not reverse
        self._refresh_issue_list()

    def filter_issues(self, _event: Optional[tk.Event] = None) -> None:
        """Filter issues based on the search entry, selected files and severity."""
        term = self.search_var.get().lower()
        selected_files = [name for name, var in self.file_vars.items() if var.get()]
        selected_severity = self.severity_var.get()

        filtered = [
            issue
            for issue in self.issues
            if (not selected_files or issue.get("file", "") in selected_files)
        ]
        if selected_severity != "All severities":
            sev_value = SEVERITY_NAME_TO_VALUE.get(selected_severity)
            filtered = [
                issue
                for issue in filtered
                if issue.get("severity") == sev_value
            ]
        if term:
            filtered = [
                issue
                for issue in filtered
                if term in issue["host"].lower()
                or term in issue["protocol"].lower()
                or term in str(issue.get("severity", "")).lower()
                or term
                in SEVERITY_NAMES.get(str(issue.get("severity", "")), "").lower()
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
            self.copy_button.state(["!disabled"])
            self.send_ports_button.state(["!disabled"])
        else:
            self.port_text.insert(tk.END, "None")
            self.copy_button.state(["disabled"])
            self.send_ports_button.state(["disabled"])
        self.port_text.config(state=tk.DISABLED)

    def clear_filter(self) -> None:
        """Clear the search and severity filters and show all issues."""
        self.search_var.set("")
        self.severity_var.set("All severities")
        self.filter_issues()

    def _show_issue_menu(self, event: tk.Event) -> None:
        """Display the context menu for the issue list."""
        item = self.issue_tree.identify_row(event.y)
        if item:
            if item not in self.issue_tree.selection():
                self.issue_tree.selection_set(item)
        try:
            self.issue_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.issue_menu.grab_release()

    def copy_selected_hosts_ports(self) -> None:
        """Copy selected host:port pairs to the clipboard."""
        selection = self.issue_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "No issues selected.")
            return
        lines = []
        for item in selection:
            index = self.issue_tree.index(item)
            issue = self.visible_issues[index]
            lines.append(f"{issue['host']}:{issue['port']}")
        data = "\n".join(lines)
        self.clipboard_clear()
        self.clipboard_append(data)
        messagebox.showinfo("Copied", "Hosts and ports copied to clipboard.")

    def copy_ports(self) -> None:
        """Copy the comma-separated list of open ports to the clipboard."""
        if not self.ports:
            messagebox.showwarning("No Ports", "No open ports to copy.")
            return
        ports_sorted = ",".join(str(p) for p in sorted(self.ports))
        self.clipboard_clear()
        self.clipboard_append(ports_sorted)
        messagebox.showinfo("Copied", "Open ports copied to clipboard.")

    def _build_script_builder_tab(self, parent: tk.Widget) -> None:
        """Initialize widgets used for building scripts."""

        table_frame = ttk.LabelFrame(parent, text="Hosts & Ports")
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        tree_container = ttk.Frame(table_frame)
        tree_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        tree_scrollbar = ttk.Scrollbar(tree_container, orient=tk.VERTICAL)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.script_entry_tree = ttk.Treeview(
            tree_container,
            columns=("host", "port"),
            show="headings",
            height=6,
        )
        self.script_entry_tree.heading("host", text="Host")
        self.script_entry_tree.heading("port", text="Port")
        self.script_entry_tree.column("host", width=200, stretch=True)
        self.script_entry_tree.column("port", width=80, stretch=False, anchor=tk.CENTER)
        self.script_entry_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.script_entry_tree.configure(yscrollcommand=tree_scrollbar.set)
        tree_scrollbar.configure(command=self.script_entry_tree.yview)

        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, padx=5)
        self.import_script_button = ttk.Button(
            control_frame,
            text="Import Hosts & Ports",
            command=self.import_script_builder_entries,
        )
        self.import_script_button.pack(anchor=tk.W, pady=(0, 5))

        self.export_script_button = ttk.Button(
            control_frame,
            text="Export Hosts & Ports",
            command=self.export_script_builder_entries,
        )
        self.export_script_button.pack(anchor=tk.W, pady=(0, 5))
        self.export_script_button.state(["disabled"])

        self.clear_script_button = ttk.Button(
            control_frame,
            text="Clear Hosts & Ports",
            command=self.clear_script_builder_entries,
        )
        self.clear_script_button.pack(anchor=tk.W, pady=(0, 5))
        self.clear_script_button.state(["disabled"])

        template_frame = ttk.LabelFrame(parent, text="Command Template")
        template_frame.pack(fill=tk.BOTH, expand=False, padx=5, pady=(0, 5))
        selection_frame = ttk.Frame(template_frame)
        selection_frame.pack(fill=tk.X, padx=5, pady=(5, 0))
        ttk.Label(selection_frame, text="Saved Templates:").pack(
            side=tk.LEFT, padx=(0, 5)
        )
        self.selected_template_var = tk.StringVar(value="Custom")
        self.template_selector = ttk.Combobox(
            selection_frame,
            textvariable=self.selected_template_var,
            state="readonly",
            width=25,
        )
        self.template_selector.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.template_selector.bind(
            "<<ComboboxSelected>>", self._on_script_template_selected
        )
        self.selected_template_var.trace_add(
            "write", lambda *_: self._update_template_button_state()
        )
        ttk.Button(
            selection_frame,
            text="Load",
            command=self._on_script_template_selected,
        ).pack(side=tk.LEFT, padx=(5, 0))

        ttk.Label(
            template_frame,
            text="Use <host> and <port> placeholders to build commands.",
        ).pack(anchor=tk.W, padx=5, pady=(5, 0))
        self.script_template_text = tk.Text(template_frame, height=5, wrap="word")
        self.script_template_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        save_frame = ttk.Frame(template_frame)
        save_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        ttk.Label(save_frame, text="Template Name:").pack(side=tk.LEFT)
        self.new_template_name_var = tk.StringVar()
        name_entry = ttk.Entry(save_frame, textvariable=self.new_template_name_var, width=20)
        name_entry.pack(side=tk.LEFT, padx=(5, 5), fill=tk.X, expand=True)
        ttk.Button(
            save_frame,
            text="Save Template",
            command=self.save_script_template,
        ).pack(side=tk.LEFT)
        self.delete_template_button = ttk.Button(
            save_frame,
            text="Delete Template",
            command=self.delete_script_template,
        )
        self.delete_template_button.pack(side=tk.LEFT, padx=(5, 0))
        self.delete_template_button.state(["disabled"])

        action_frame = ttk.Frame(parent)
        action_frame.pack(fill=tk.X, padx=5)
        self.build_script_button = ttk.Button(
            action_frame, text="Build Script", command=self.build_script
        )
        self.build_script_button.pack(side=tk.LEFT, pady=(0, 5))

        self.copy_script_button = ttk.Button(
            action_frame, text="Copy Script", command=self.copy_script_output
        )
        self.copy_script_button.pack(side=tk.LEFT, padx=(5, 0), pady=(0, 5))
        self.copy_script_button.state(["disabled"])

        output_frame = ttk.LabelFrame(parent, text="Generated Script")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))
        self.script_output_text = tk.Text(output_frame, height=10, wrap="word")
        self.script_output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.script_output_text.config(state=tk.DISABLED)

        self._update_template_combobox()

    def _update_script_builder_lists(self) -> None:
        """Refresh the host/port table and button states."""

        self.script_entry_tree.delete(*self.script_entry_tree.get_children())
        for host, port in sorted(
            self.script_entries,
            key=lambda item: (
                item[0] or "",  # sort empty hosts first alphabetically
                item[1] if item[1] is not None else -1,
            ),
        ):
            display_port = "" if port is None else str(port)
            self.script_entry_tree.insert("", tk.END, values=(host or "", display_port))

        if self.script_entries:
            self.clear_script_button.state(["!disabled"])
            self.export_script_button.state(["!disabled"])
        else:
            self.clear_script_button.state(["disabled"])
            self.export_script_button.state(["disabled"])

    def add_to_script_builder(
        self, entries: Iterable[Tuple[Optional[str], Optional[int]]]
    ) -> None:
        """Add host/port combinations to the script builder."""

        added = False
        for host, port in entries:
            normalized_host = host or None
            normalized_port = port if port else None
            key = (normalized_host, normalized_port)
            if key not in self._script_entry_set:
                self._script_entry_set.add(key)
                self.script_entries.append(key)
                added = True

        if added:
            self._update_script_builder_lists()

    def import_script_builder_entries(self) -> None:
        """Load host and port entries from a text file."""

        file_path = filedialog.askopenfilename(
            title="Import Hosts & Ports",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not file_path:
            return

        entries: List[Tuple[Optional[str], Optional[int]]] = []
        invalid_lines: List[str] = []

        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                for line_no, raw_line in enumerate(fh, start=1):
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue

                    host_part, separator, port_part = line.partition(":")
                    host = host_part.strip() or None
                    port: Optional[int]

                    if separator:
                        port_str = port_part.strip()
                        if port_str:
                            try:
                                port = int(port_str)
                            except ValueError:
                                invalid_lines.append(f"Line {line_no}: invalid port '{port_str}'")
                                continue
                            if port <= 0 or port > 65535:
                                invalid_lines.append(
                                    f"Line {line_no}: port out of range '{port_str}'"
                                )
                                continue
                        else:
                            port = None
                    else:
                        port = None

                    if host is None and port is None:
                        invalid_lines.append(f"Line {line_no}: no host or port specified")
                        continue

                    entries.append((host, port))
        except OSError as exc:
            messagebox.showerror("Import Failed", f"Could not read file:\n{exc}")
            return

        if not entries:
            message = "No valid host or port entries were found in the selected file."
            if invalid_lines:
                message += "\n\n" + "\n".join(invalid_lines)
            messagebox.showwarning("No Entries Imported", message)
            return

        before_count = len(self.script_entries)
        self.add_to_script_builder(entries)
        after_count = len(self.script_entries)

        if after_count == before_count:
            messagebox.showinfo(
                "No New Entries",
                "All entries from the file were already present in the Script Builder.",
            )
        else:
            messagebox.showinfo(
                "Import Complete",
                f"Imported {after_count - before_count} new host/port entries.",
            )

        if invalid_lines:
            messagebox.showwarning(
                "Some Entries Skipped",
                "\n".join(invalid_lines),
            )

    def export_script_builder_entries(self) -> None:
        """Save current host and port entries to a text file."""

        if not self.script_entries:
            messagebox.showwarning(
                "No Entries", "Add hosts or ports before exporting to a file."
            )
            return

        file_path = filedialog.asksaveasfilename(
            title="Export Hosts & Ports",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as fh:
                for host, port in sorted(
                    self.script_entries,
                    key=lambda item: (
                        item[0] or "",
                        item[1] if item[1] is not None else -1,
                    ),
                ):
                    host_part = host or ""
                    if port is not None:
                        if host_part:
                            fh.write(f"{host_part}:{port}\n")
                        else:
                            fh.write(f":{port}\n")
                    else:
                        fh.write(f"{host_part}\n")
        except OSError as exc:
            messagebox.showerror("Export Failed", f"Could not write file:\n{exc}")
            return

        messagebox.showinfo("Export Complete", f"Saved entries to {file_path}.")

    def clear_script_builder_entries(self) -> None:
        """Remove all hosts and ports stored for script building."""

        if not self.script_entries:
            return
        self.script_entries.clear()
        self._script_entry_set.clear()
        self._update_script_builder_lists()

    def send_selected_to_script_builder(self) -> None:
        """Send selected issue hosts and ports to the script builder."""

        selection = self.issue_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "No issues selected.")
            return

        entries: List[Tuple[Optional[str], Optional[int]]] = []
        for item in selection:
            index = self.issue_tree.index(item)
            try:
                issue = self.visible_issues[index]
            except IndexError:
                continue
            host = issue["host"]
            port_value = issue.get("port")
            port = port_value if isinstance(port_value, int) and port_value else None
            entries.append((host, port))

        self.add_to_script_builder(entries)
        if entries:
            messagebox.showinfo(
                "Added",
                "Selected hosts and ports added to the Script Builder tab.",
            )

    def send_ports_to_script_builder(self) -> None:
        """Add the current set of ports to the script builder."""

        if not self.ports:
            messagebox.showwarning("No Ports", "No open ports to send.")
            return
        self.add_to_script_builder((None, port) for port in self.ports)
        messagebox.showinfo("Added", "Ports added to the Script Builder tab.")

    def build_script(self) -> None:
        """Generate a bash script from the stored hosts, ports, and template."""

        template = self.script_template_text.get("1.0", tk.END).strip()
        if not template:
            messagebox.showwarning(
                "Missing Template", "Enter a command template before building."
            )
            return

        host_port_pairs = [
            (host, port)
            for host, port in self.script_entries
            if host and port is not None
        ]
        hosts = sorted({host for host, _ in self.script_entries if host})
        ports = sorted({port for _, port in self.script_entries if port is not None})

        use_host = "<host>" in template
        use_port = "<port>" in template

        if use_host and not hosts:
            messagebox.showwarning(
                "Missing Hosts", "Add at least one host to the Script Builder."
            )
            return
        if use_port and not ports:
            messagebox.showwarning(
                "Missing Ports", "Add at least one port to the Script Builder."
            )
            return

        script_lines: List[str] = ["#!/usr/bin/env bash", ""]

        if use_host and use_port:
            if not host_port_pairs:
                messagebox.showwarning(
                    "Missing Host/Port Pairs",
                    "Add entries that include both a host and a port to use both placeholders.",
                )
                return
            for host, port in sorted(host_port_pairs):
                line = template.replace("<host>", host).replace("<port>", str(port))
                script_lines.append(line)
        elif use_host:
            for host in hosts:
                line = template.replace("<host>", host)
                script_lines.append(line)
        elif use_port:
            for port in ports:
                line = template.replace("<port>", str(port))
                script_lines.append(line)
        else:
            script_lines.append(template)

        script_output = "\n".join(script_lines)
        self.script_output_text.config(state=tk.NORMAL)
        self.script_output_text.delete("1.0", tk.END)
        self.script_output_text.insert(tk.END, script_output)
        self.script_output_text.config(state=tk.DISABLED)
        self.copy_script_button.state(["!disabled"])

    def _update_template_combobox(self) -> None:
        """Refresh the saved template selector with current templates."""

        if not hasattr(self, "template_selector"):
            return
        options = ["Custom"] + sorted(self.script_templates)
        self.template_selector["values"] = options
        if self.selected_template_var.get() not in options:
            self.selected_template_var.set("Custom")
        self._update_template_button_state()

    def _on_script_template_selected(self, _event: Optional[tk.Event] = None) -> None:
        """Load the selected template into the editor."""

        choice = self.selected_template_var.get()
        if choice == "Custom":
            self._update_template_button_state()
            return
        template = self.script_templates.get(choice, "")
        self.script_template_text.delete("1.0", tk.END)
        self.script_template_text.insert(tk.END, template)
        self.new_template_name_var.set(choice)
        self._update_template_button_state()

    def save_script_template(self) -> None:
        """Save the current template to the library for future use."""

        name = self.new_template_name_var.get().strip()
        if not name:
            messagebox.showwarning(
                "Missing Name", "Enter a name before saving the template."
            )
            return
        if name == "Custom":
            messagebox.showwarning(
                "Reserved Name",
                "Choose a different name; 'Custom' is reserved for unsaved templates.",
            )
            return

        template = self.script_template_text.get("1.0", tk.END).strip()
        if not template:
            messagebox.showwarning(
                "Missing Template",
                "Enter a command template before saving.",
            )
            return

        if name in self.script_templates:
            overwrite = messagebox.askyesno(
                "Overwrite Template",
                f"A template named '{name}' already exists. Overwrite it?",
            )
            if not overwrite:
                return

        self.script_templates[name] = template
        self.selected_template_var.set(name)
        self._update_template_combobox()
        self._save_config()
        messagebox.showinfo("Template Saved", f"Template '{name}' saved for future use.")

    def delete_script_template(self) -> None:
        """Remove the selected saved template from the library."""

        choice = self.selected_template_var.get()
        if choice == "Custom":
            messagebox.showinfo(
                "Select Template", "Choose a saved template to delete."
            )
            return
        if choice not in self.script_templates:
            messagebox.showwarning(
                "Template Missing",
                "The selected template could not be found. Please refresh and try again.",
            )
            self._update_template_combobox()
            return

        confirm = messagebox.askyesno(
            "Delete Template", f"Delete the saved template '{choice}'?"
        )
        if not confirm:
            return

        del self.script_templates[choice]
        self.selected_template_var.set("Custom")
        self.new_template_name_var.set("")
        self._update_template_combobox()
        self._save_config()
        messagebox.showinfo(
            "Template Deleted", f"Template '{choice}' has been removed."
        )

    def _update_template_button_state(self) -> None:
        """Enable or disable template actions based on the selection."""

        if not hasattr(self, "delete_template_button"):
            return
        choice = self.selected_template_var.get()
        if choice != "Custom" and choice in self.script_templates:
            self.delete_template_button.state(["!disabled"])
        else:
            self.delete_template_button.state(["disabled"])

    def copy_script_output(self) -> None:
        """Copy the generated script to the clipboard."""

        script = self.script_output_text.get("1.0", tk.END).strip()
        if not script:
            messagebox.showwarning("No Script", "Build a script before copying.")
            return
        self.clipboard_clear()
        self.clipboard_append(script)
        messagebox.showinfo("Copied", "Script copied to clipboard.")

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
        selection = self.issue_tree.selection()
        if not selection:
            return
        # ``Treeview.selection`` returns item identifiers which may not be
        # plain integers (for example, automatically generated IDs like
        # ``I001``).  Use ``Treeview.index`` to translate the identifier into
        # the corresponding position within the widget and map that to the
        # ``visible_issues`` list.
        index = self.issue_tree.index(selection[0])
        issue = self.visible_issues[index]

        # Build the textual portion of the details view.
        details = [
            f"Host: {issue['host']}",
            f"Port: {issue['port']}/{issue['protocol']}",
            f"Severity: {self._format_severity(issue.get('severity'))}",
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

        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, "\n".join(details))
        self.detail_text.config(state=tk.DISABLED)

        # Populate the reference table.
        self.ref_tree.delete(*self.ref_tree.get_children())
        for ref in issue.get("cve", []):
            self.ref_tree.insert("", tk.END, values=("CVE", ref))
        for ref in issue.get("bid", []):
            self.ref_tree.insert("", tk.END, values=("BID", ref))
        for ref in issue.get("xref", []):
            self.ref_tree.insert("", tk.END, values=("XREF", ref))


if __name__ == "__main__":
    app = NessusViewer()
    app.mainloop()
