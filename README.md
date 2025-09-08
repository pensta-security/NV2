# NV2

Utilities for analyzing vulnerability reports.

## Nessus Viewer

`nessus_viewer.py` provides a simple Tkinter GUI for examining one or more
Nessus (`.nessus`) files:

- Open files via **File > Open Nessus Files**.
- Quickly import previous files through **File > Recent Files**, which keeps
  the last ten entries. Selecting multiple entries in succession adds them to
  the current view.
- The left pane lists discovered issues. Double-click an entry to view
  detailed information.
- Select one or more issues and right-click to copy their host:port pairs to
  the clipboard, one per line.
- A search box above the list filters issues by any text, including host,
  plugin name, severity, or source file.
- The bottom of the window shows which Nessus files were opened and all unique
  open TCP/UDP ports, sorted in ascending order and separated by commas.
