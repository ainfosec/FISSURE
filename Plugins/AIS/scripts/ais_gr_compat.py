"""Version-aware GNU Radio validation shared by the AIS plugin helpers.

The supported API boundary is GNU Radio 3.8 and 3.10. C++ OOT modules
(gr-ais and gr-osmosdr) must be compiled for the matching GNU Radio runtime.
"""

def gr_minor_version(gr):
    version = gr.version() if callable(getattr(gr, "version", None)) else str(getattr(gr, "__version__", ""))
    version = str(version)
    parts = version.split(".")
    if len(parts) < 2 or parts[0] != "3" or parts[1] not in ("8", "10"):
        raise RuntimeError("Unsupported GNU Radio version %r; expected 3.8 or 3.10" % version)
    return int(parts[1]), version
