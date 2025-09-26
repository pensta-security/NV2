# Pentest Slayer

Utilities for analyzing vulnerability reports.

## Pentest Slayer

`pentest_slayer.py` provides a simple Tkinter GUI for examining one or more
Nessus (`.nessus`) and Nmap (`.xml`) files:

- Open Nessus files via **File > Open Nessus Files**. Nmap XML can be loaded
  from **Nmap > Open Nmap XML**. Both menus keep the ten most recent files for
  quick access.
- The **Nessus Records** tab lists vulnerability findings. Double-click an
  entry to view detailed information.
- The **Nmap Records** tab mirrors that experience for port-scan data,
  including service details and script output where available.
- Right-click either table to copy selected host:port pairs or send them to
  the Script Builder.
- Each tab exposes search and filter controls tailored to the available data
  (severity for Nessus, port state for Nmap).
- The **Files & Ports** tab now summarises the files opened for each scanner
  and lists the associated ports. Nessus ports reflect open findings, and the
  Nmap list shows open ports by default (or any state chosen in the Nmap tab).
  Both lists can be copied or sent directly to the Script Builder.
