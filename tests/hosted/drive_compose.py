#!/usr/bin/env python3
"""Drive a single Enter (no body) or type+send into a minifb window.
Each invocation opens a fresh X11 connection and exits — same pattern
as drive_link.py. Keeping the connection short sidesteps the stale-
X11-state hangs we hit when reusing a single display across long-
running test scripts.

Usage:
  drive_compose.py <window-id>          # press Enter once
                                        # (dismiss QR modal, or open
                                        # the Thread for the focused
                                        # contact row, or commit a
                                        # transient modal)
  drive_compose.py <window-id> <body>   # type body, press Enter (send)
                                        # — assumes Screen::Thread is
                                        # already open. Caller must
                                        # have pressed Enter on
                                        # Screen::Home first if this
                                        # is the first compose.
                                        # Subsequent composes on the
                                        # same Thread stay on Thread
                                        # after send (gam_app:1200
                                        # only backs out when the
                                        # compose buffer is empty), so
                                        # repeated invocations don't
                                        # need a re-open.
"""

import ctypes
import os
import sys
import time

DISPLAY = os.environ.get("DISPLAY", "localhost:10.0")

X11 = ctypes.cdll.LoadLibrary("libX11.so.6")
c_ulong, c_int, c_uint = ctypes.c_ulong, ctypes.c_int, ctypes.c_uint
X11.XOpenDisplay.restype = ctypes.c_void_p
X11.XOpenDisplay.argtypes = [ctypes.c_char_p]
X11.XDefaultRootWindow.restype = c_ulong
X11.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
X11.XKeysymToKeycode.restype = c_uint
X11.XKeysymToKeycode.argtypes = [ctypes.c_void_p, c_ulong]
X11.XFlush.argtypes = [ctypes.c_void_p]
X11.XSendEvent.restype = c_int
X11.XSendEvent.argtypes = [ctypes.c_void_p, c_ulong, c_int, c_ulong, ctypes.c_void_p]


class XEvent(ctypes.Union):
    class XKeyEvent(ctypes.Structure):
        _fields_ = [
            ("type", c_int), ("serial", c_ulong), ("send_event", c_int),
            ("display", ctypes.c_void_p), ("window", c_ulong), ("root", c_ulong),
            ("subwindow", c_ulong), ("time", c_ulong),
            ("x", c_int), ("y", c_int), ("x_root", c_int), ("y_root", c_int),
            ("state", c_uint), ("keycode", c_uint), ("same_screen", c_int),
        ]
    _fields_ = [("key", XKeyEvent), ("pad", ctypes.c_char * 192)]


def press(dpy, win, root, kc, wait):
    ev = XEvent()
    ev.key.type = 2
    ev.key.send_event = 1
    ev.key.display = dpy
    ev.key.window = win
    ev.key.root = root
    ev.key.same_screen = 1
    ev.key.keycode = kc
    X11.XSendEvent(dpy, win, 1, 1, ctypes.byref(ev))
    X11.XFlush(dpy)
    time.sleep(0.05)
    ev.key.type = 3
    X11.XSendEvent(dpy, win, 1, 2, ctypes.byref(ev))
    X11.XFlush(dpy)
    time.sleep(wait)


def keycode(dpy, keysym):
    return X11.XKeysymToKeycode(dpy, ctypes.c_ulong(keysym))


def main():
    if len(sys.argv) not in (2, 3):
        print("usage: drive_compose.py <window-id> [body]", file=sys.stderr)
        sys.exit(2)
    win = int(sys.argv[1], 0)
    body = sys.argv[2] if len(sys.argv) == 3 else None

    dpy = X11.XOpenDisplay(DISPLAY.encode())
    if not dpy:
        print(f"ERROR: cannot open display {DISPLAY}", file=sys.stderr)
        sys.exit(1)
    root = X11.XDefaultRootWindow(dpy)

    kc_return = keycode(dpy, 0xFF0D)

    if body is None:
        # Single Enter — dismiss QR modal, or open Thread for the
        # currently-focused contact row.
        press(dpy, win, root, kc_return, 0.5)
        return

    # Type the body into the open Thread's compose buffer. Map each
    # ASCII char to its keysym (printable ASCII keysyms equal their
    # ASCII codes per X11.h).
    for ch in body:
        kc = keycode(dpy, ord(ch))
        press(dpy, win, root, kc, 0.08)

    # Enter to send. Thread Enter with a non-empty buffer triggers
    # Cmd::SendMessage; with an empty buffer it backs out to Home.
    # That's why we never lead with an Enter here — leading-Enter
    # on an already-open Thread would empty-back-out before the
    # body lands.
    press(dpy, win, root, kc_return, 1.0)


if __name__ == "__main__":
    main()
