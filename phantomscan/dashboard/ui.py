allow_exit = False
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.console import Console

import termios
import tty
import psutil
import time
import itertools
import sys

from collections import deque

console = Console()

# -----------------------------
# GLOBAL STATE
# -----------------------------
log_buffer = deque(maxlen=20)
current_tool = "idle"

progress = {
    "Recon": 0,
    "Scanning": 0,
    "Exploitation": 0,
    "Reporting": 0
}

# -----------------------------
# LOG SYSTEM
# -----------------------------
def log(message):
    log_buffer.append(str(message))


def update_progress(stage, value):
    progress[stage] = value


# -----------------------------
# GRAPH HELPER
# -----------------------------
def create_bar(percentage, length=20):
    filled = int((percentage / 100) * length)
    empty = length - filled
    bar = "█" * filled + "-" * empty
    return f"[{bar}] {percentage}%"


# -----------------------------
# PANELS
# -----------------------------
def ram_panel():
    ram = psutil.virtual_memory().percent
    return Panel(create_bar(ram), title="RAM")


def cpu_panel():
    cpu = psutil.cpu_percent()
    return Panel(create_bar(cpu), title="CPU")


def logo_panel():
    logo = """
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
"""
    return Panel(logo, title="PhantomScan")


def warning_panel():
    return Panel("⚠ Press 'q' to exit | Use only for ethical testing", title="Warning")


# -----------------------------
# LOCK ANIMATION
# -----------------------------
lock_frames = [
"""
     access
  secure   protect

        🔒

  defend   encrypt
     monitor
""",
"""
     monitor
  access   secure

        🔒

  protect   defend
     encrypt
""",
"""
     encrypt
  monitor   access

        🔒

  secure   protect
     defend
""",
"""
     defend
  encrypt   monitor

        🔒

  access   secure
     protect
"""
]


def lock_panel(frame):
    return Panel(frame, title="Security Core")


def scanner_panel():
    content = "\n".join(log_buffer)
    return Panel(content or "Waiting...", title="Scanner Output")


def tools_panel():
    return Panel(f"Running Tool:\n\n{current_tool}", title="Tools")


def progress_panel():
    content = ""
    for stage, value in progress.items():
        bar = create_bar(value, length=15)
        content += f"{stage:<12} {bar}\n"
    return Panel(content, title="Progress")


# -----------------------------
# LAYOUT
# -----------------------------
def generate_layout():
    layout = Layout()

    layout.split_column(
        Layout(name="row1", size=8),
        Layout(name="row2")
    )

    layout["row1"].split_row(
        Layout(name="ram", ratio=1),
        Layout(name="cpu", ratio=1),
        Layout(name="logo", ratio=3),
        Layout(name="warning", ratio=1),
    )

    layout["row2"].split_row(
        Layout(name="lock", ratio=1),
        Layout(name="scanner", ratio=2),
        Layout(name="right", ratio=1),
    )

    layout["right"].split_column(
        Layout(name="tools"),
        Layout(name="progress")
    )

    return layout


# -----------------------------
# NON-BLOCKING KEY DETECTION
# -----------------------------


def get_key():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    try:
        tty.setcbreak(fd)
        if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
            return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    return None


# -----------------------------
# MAIN DASHBOARD LOOP
# -----------------------------
def run_dashboard():

    layout = generate_layout()
    frames = itertools.cycle(lock_frames)

    with Live(layout, refresh_per_second=2, screen=True, console=console):

        while True:
            try:
                # 🔥 Exit on 'q'
                key = get_key()
                if allow_exit and key and key.lower() == "q":
                    console.print("\n[bold red]Exiting PhantomScan...[/bold red]")
                    time.sleep(1)
                    break

                layout["ram"].update(ram_panel())
                layout["cpu"].update(cpu_panel())
                layout["logo"].update(logo_panel())
                layout["warning"].update(warning_panel())

                layout["lock"].update(lock_panel(next(frames)))
                layout["scanner"].update(scanner_panel())
                layout["tools"].update(tools_panel())
                layout["progress"].update(progress_panel())

                time.sleep(0.5)

            except Exception as e:
                console.print(f"[red]UI Error: {e}[/red]")
                break
