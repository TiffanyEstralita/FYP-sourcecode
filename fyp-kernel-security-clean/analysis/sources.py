"""
Shared helper: where the netfilter source files are.

Besides the real .c files, this creates "expanded template" files for ipset.
ipset keeps shared code in two header files (ip_set_bitmap_gen.h,
ip_set_hash_gen.h) written with placeholder names such as `mtype_add`.
Each ipset .c file sets e.g. `#define MTYPE bitmap_ip` and then includes the
header, so the compiler turns `mtype_add` into `bitmap_ip_add`.

expand_ipset_templates() does the same substitution and saves one filled-in
copy per MTYPE, named "<MTYPE>@<header>", e.g. "bitmap_ip@ip_set_bitmap_gen.h".
Line numbers in the copy match the original header.

Usage from a script in analysis/<folder>/:
    sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
    from sources import find_source, all_source_files
"""

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

NETFILTER_PATH = PROJECT_ROOT / "data/kernel/linux-shallow/net/netfilter"
EXPANDED_PATH = PROJECT_ROOT / "results/raw/expanded_templates"

TEMPLATE_HEADERS = ("ip_set_bitmap_gen.h", "ip_set_hash_gen.h")
MTYPE_PATTERN = re.compile(r'^#define\s+MTYPE\s+(\w+)')
INCLUDE_PATTERN = re.compile(r'^#include\s+"([\w.]+\.h)"')


def expanded_name(mtype, header):
    return f"{mtype}@{header}"


def template_prefix(filename):
    """'bitmap_ip@ip_set_bitmap_gen.h' -> 'bitmap_ip_' (None for normal files)"""
    if "@" not in filename:
        return None
    return filename.split("@")[0] + "_"


def template_uses():
    """List of (c file name, MTYPE, header) for every template include in ipset"""
    uses = []
    for c_file in sorted((NETFILTER_PATH / "ipset").glob("*.c")):
        mtype = None
        for line in c_file.read_text(errors="ignore").split("\n"):
            m = MTYPE_PATTERN.match(line)
            if m:
                mtype = m.group(1)
            inc = INCLUDE_PATTERN.match(line)
            if inc and inc.group(1) in TEMPLATE_HEADERS and mtype:
                uses.append((c_file.name, mtype, inc.group(1)))
    return uses


def expand_ipset_templates():
    """Write one filled-in copy of each template header per MTYPE; return their paths"""
    EXPANDED_PATH.mkdir(parents=True, exist_ok=True)
    headers = {name: (NETFILTER_PATH / "ipset" / name).read_text(errors="ignore")
               for name in TEMPLATE_HEADERS}

    written = []
    for _, mtype, header in template_uses():
        text = re.sub(r'\bmtype_(\w+)', mtype + r'_\1', headers[header])
        text = re.sub(r'\bmtype\b', mtype, text)
        out = EXPANDED_PATH / expanded_name(mtype, header)
        out.write_text(text)
        written.append(out)
    return written


def compilation_units():
    """{file name: the .c file it is compiled as part of} - a template copy
    belongs to the .c file that includes it; a .c file belongs to itself"""
    return {expanded_name(mtype, header): c_name for c_name, mtype, header in template_uses()}


def all_source_files():
    """Every file to analyse: netfilter .c files + the expanded template copies"""
    return sorted(NETFILTER_PATH.rglob("*.c")) + sorted(EXPANDED_PATH.glob("*@*.h"))


def find_source(filename):
    """Path of a source file given just its name (as stored in functions_v2.json)"""
    if "@" in filename:
        path = EXPANDED_PATH / filename
        return path if path.exists() else None
    return next(NETFILTER_PATH.rglob(filename), None)
