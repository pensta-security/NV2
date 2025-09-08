# NV2

Utilities for analyzing vulnerability reports.

## Nessus Viewer

`nessus_viewer.py` provides a simple Tkinter GUI for examining one or more
Nessus (`.nessus`) files:

- Open files via **File > Open Nessus Files**.
- The left pane lists discovered issues. Double-click an entry to view
  detailed information.
- The bottom of the window shows all unique open TCP/UDP ports, sorted
  in ascending order and separated by commas.
