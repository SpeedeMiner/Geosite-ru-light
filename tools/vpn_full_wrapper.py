#!/usr/bin/env python3
"""Use the reviewed adapter unchanged except for a bounded batch size."""
import sys
from pathlib import Path

adapter=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(adapter.parent))
import vpnobratno_get
vpnobratno_get.MAX_TARGETS=100
sys.argv=[str(adapter),*sys.argv[2:]]
raise SystemExit(vpnobratno_get.main())
