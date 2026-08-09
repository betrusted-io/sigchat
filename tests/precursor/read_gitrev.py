#!/usr/bin/env python3
"""Read the ACTIVE SoC gateware version of a Precursor in update mode.

Pure USB reads: reuses usb_update.py's PrecursorUsb.load_csrs(), which
burst-reads the csr.csv descriptor at 0x20277000 and sha512-verifies it.
No halt, no poke, no reset, no flash writes — safe to run before picking
the --git-describe / --git-rev pins (BUILDING.md §3.2), including on
units whose loader-mode iSerial is empty.

Run it wherever the Precursor's USB is plugged in (build host or Pi rig).
usb_update.py must be importable: same directory as this script,
$XOUS_CORE_DIR/tools, or ../../../xous-core/tools relative to this file
(the §1 sibling layout). Deps are usb_update.py's own: pyusb,
progressbar2, pycryptodome.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CANDIDATES = [
    HERE,
    os.path.join(os.environ.get('XOUS_CORE_DIR', ''), 'tools'),
    os.path.normpath(os.path.join(HERE, '..', '..', '..', 'xous-core', 'tools')),
]
for d in CANDIDATES:
    if d and os.path.isfile(os.path.join(d, 'usb_update.py')):
        sys.path.insert(0, d)
        break
else:
    print("ERROR: usb_update.py not found (looked in: %s)"
          % ', '.join(c for c in CANDIDATES if c))
    sys.exit(2)

import usb.core
from usb_update import PrecursorUsb

dev = usb.core.find(idProduct=0x5bf0, idVendor=0x1209)
if dev is None:
    print("ERROR: no Precursor in update mode found (USB 1209:5bf0)")
    sys.exit(2)
dev.set_configuration()
p = PrecursorUsb(dev)
p.load_csrs()  # prints "Using SoC <gitrev> registers"; exits 1 on bad descriptor
print("GITREV=%s" % p.gitrev)
print("Suggested pins: GIT_DESCRIBE=%s GIT_REV=%s"
      % (p.gitrev, p.gitrev.rsplit('g', 1)[-1]))
