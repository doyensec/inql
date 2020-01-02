"""
STUB file to make stickytape happy with import from __future__ statements.
"""

import platform

if platform.system() == "Java":
	from burp_ext.extender import BurpExtender