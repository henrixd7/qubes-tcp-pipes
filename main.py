#!/usr/bin/python3
"""Qubes TCP Pipes - main entry point.

Runs as a package (python3 main.py) or as the single-file build
output (python3 qubes-tcp-pipes.py).
"""

import tkinter as tk

try:
    from app.ui import QubePipesApp  # package mode
except ImportError:
    pass  # single-file build: QubePipesApp is in global scope


def main():
    root = tk.Tk()
    root.minsize(800, 600)
    app = QubePipesApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
