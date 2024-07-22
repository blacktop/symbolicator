# -*- coding: utf-8 -*-

# MIT License
#
# Copyright (c) 2024 blacktop
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import re
from collections import Counter, deque
from typing import Dict, Iterable, Optional

import ida_funcs
import ida_idp
import ida_ua
import ida_xref
import idaapi
import idautils
import idc
from idadex import ea_t
from macho import get_section_by_name

from symbolicator import Anchor, Signature, Symbolicator, Version


def get_func_start(ea: ea_t) -> Optional[ea_t]:
    return ida_funcs.get_func(ea).start_ea


def get_func_end(ea: ea_t) -> int:
    return ida_funcs.get_func(ea).end_ea


def get_func_arg_count(ea: ea_t) -> int:
    func = ida_funcs.get_func(ea)
    if not func:
        return 0
    return func.regargqty


def get_unique_cstrings(segment: str, section: str) -> Iterable[idautils.Strings]:
    strings = []
    start, end = get_section_by_name(segment, section)
    if not start or not end:
        return strings
    print(f"🔍 Searching for unique strings in {segment}.{section} section:\n    - 0x{start:x}-0x{end:x}")
    for string in idautils.Strings():
        # filter out strings that are not in the section
        if start <= string.ea < end:
            strings.append(string)
    # Count the occurrences of each content
    counts = Counter(str(info) for info in strings)
    # Filter StringItem objects that have unique content
    unique_strings = [info for info in strings if counts[str(info)] == 1]
    print(f"    🧵 Found {len(strings)} strings ({len(unique_strings)} unique)")
    return unique_strings


def get_xrefs(ea: ea_t) -> Iterable[ea_t]:
    xrefs = []
    next_ea = ida_xref.get_first_dref_to(ea)
    while next_ea != idaapi.BADADDR:
        xrefs.append(next_ea)
        next_ea = ida_xref.get_next_dref_to(ea, next_ea)
    return xrefs


def find_function_calling_string(curr_addr, trace=False):
    func = ida_funcs.get_func(curr_addr)
    if not func:
        return None

    func_start = func.start_ea
    func_end = func.end_ea

    # Use a queue to manage forked paths
    address_queue = deque([(curr_addr, set())])

    while address_queue:
        curr_addr, visited = address_queue.popleft()

        while func_start <= curr_addr < func_end:
            if curr_addr in visited:
                break

            visited.add(curr_addr)
            mnem = idc.print_insn_mnem(curr_addr)

            if mnem == "RET":
                # Terminate this path on RET instruction
                break
            elif mnem == "B":
                target = idc.get_operand_value(curr_addr, 0)
                if func_start <= target < func_end:
                    curr_addr = target
                    continue
            elif mnem == "CBNZ":
                # Fork the path: follow the branch and continue with fall-through
                target = idc.get_operand_value(curr_addr, 1)
                if func_start <= target < func_end:
                    address_queue.append((target, visited.copy()))
                # Continue with fall-through path
            elif mnem in ["BL", "BLR", "BR"]:
                if mnem == "BL":
                    target = idc.get_operand_value(curr_addr, 0)
                elif mnem in ["BLR", "BR"]:
                    reg = idc.print_operand(curr_addr, 0)
                    target = track_register_value(curr_addr, reg, func_start)

                if target != idc.BADADDR:
                    target_func = ida_funcs.get_func(target)
                    if target_func:
                        # print(f"Found function calling '{hex(curr_addr)}': {idc.get_func_name(target)}")
                        return idc.get_func_name(target)

            curr_addr = idc.next_head(curr_addr)

    print(f"No function found calling '{hex(curr_addr)}'")
    return None


def track_register_value(start_addr, reg, func_start):
    curr_addr = start_addr
    while curr_addr >= func_start:
        curr_addr = idc.prev_head(curr_addr)
        if idc.print_insn_mnem(curr_addr) == "ADRP":
            if idc.print_operand(curr_addr, 0) == reg:
                base = idc.get_operand_value(curr_addr, 1)
                next_addr = idc.next_head(curr_addr)
                if idc.print_insn_mnem(next_addr) == "ADD" and idc.print_operand(next_addr, 0) == reg:
                    offset = idc.get_operand_value(next_addr, 2)
                    return base + offset
        elif idc.print_insn_mnem(curr_addr) in ["MOV", "MOVZ", "MOVK"]:
            if idc.print_operand(curr_addr, 0) == reg:
                return idc.get_operand_value(curr_addr, 1)
    return idc.BADADDR


def get_single_ref_funcs() -> Dict:
    functions_with_single_xref = {}
    for func_ea in idautils.Functions():
        xrefs = list(idautils.CodeRefsTo(func_ea, 0))
        if len(xrefs) == 1:
            func_name = idc.get_func_name(func_ea)
            xref_name = idc.get_func_name(xrefs[0])
            if func_name.startswith("sub_F"):
                continue
            if func_name not in functions_with_single_xref:
                functions_with_single_xref[func_name] = xref_name
    return functions_with_single_xref


def get_unique_func_xref_chains(ea):
    func = idaapi.get_func(ea)
    if not func:
        print(f"No function found at address 0x{ea:X}")
        return [], []

    def follow_chain(start_ea, get_xrefs_func, direction):
        chain = [start_ea]
        current_ea = start_ea
        while True:
            xrefs = list(get_xrefs_func(current_ea, 0))
            func_xrefs = [x for x in xrefs if idaapi.get_func(x.frm if direction == "to" else x.to)]
            if len(func_xrefs) != 1:
                break
            next_ea = func_xrefs[0].frm if direction == "to" else func_xrefs[0].to
            next_func = idaapi.get_func(next_ea)
            if not next_func:
                break
            next_ea = next_func.start_ea
            if next_ea in chain:  # Avoid cycles
                break
            chain.append(next_ea)
            current_ea = next_ea
        return chain

    # Get xref chains to the function
    to_chains = []
    for xref in idautils.XrefsTo(func.start_ea, 0):
        if idaapi.get_func(xref.frm):
            chain = follow_chain(idaapi.get_func(xref.frm).start_ea, idautils.XrefsTo, "to")
            to_chains.append(list(chain))

    # Get xref chains from the function
    from_chains = []
    for xref in idautils.XrefsFrom(func.start_ea, 0):
        if idaapi.get_func(xref.to):
            to_func = idaapi.get_func(xref.to)
            if to_func.start_ea not in [chain[0] for chain in from_chains]:
                chain = follow_chain(to_func.start_ea, idautils.XrefsFrom, "from")
                from_chains.append(reversed(chain))

    # print(f"Function: {idaapi.get_func_name(ea)} ]========================>>>>>>>>>>>>>>>>>>")
    # print(f"Address: 0x{ea:X}")

    # print("\nUnique function xref chains to the function:")
    # for chain in to_chains:
    #     print("  Chain:", " -> ".join([f"0x{x:X} ({idaapi.get_func_name(x)})" for x in chain]))

    # print("\nUnique function xref chains from the function:")
    # for chain in from_chains:
    #     print("  Chain:", " -> ".join([f"0x{x:X} ({idaapi.get_func_name(x)})" for x in chain]))

    return to_chains, from_chains


def get_single_xref_from(addr):
    xrefs = list(idautils.XrefsFrom(addr, 0))
    return xrefs[0].to if len(xrefs) == 1 else None


# Usage: Call this function with the address of the function you want to analyze
# For example: get_unique_xref_chains(0x1400010A0)
def find_single_refs(sig_path: str) -> None:
    seg_start, seg_end = get_section_by_name("__TEXT_EXEC", "__text")
    unique_function_names = set()
    unique_anchor_caller = set()
    unique_backtrace_funcs = set()
    unique_symbols = set()
    regex_name = set()

    sigs = {}
    # single_ref_funcs = get_single_ref_funcs()
    sections = [
        ("__TEXT", "__cstring"),
        ("__TEXT", "__os_log"),
        ("__KLDDATA", "__cstring"),
    ]

    print("\n\n=======================================================================================")
    print("=====================[🔍 Looking for single references to strings]=====================")
    print("=======================================================================================\n")
    for segname, sectname in sections:
        for cstr in get_unique_cstrings(segname, sectname):
            # print(f'👀 for XREFs to 0x{s.address:x}: "{repr(s.content)}"')
            xrefs = get_xrefs(cstr.ea)
            if xrefs is not None and len(xrefs) == 1:
                if xrefs[0] < seg_start or xrefs[0] > seg_end:
                    continue
                # if str(cstr).startswith("/AppleInternal/Library/BuildRoots/"):
                #     # print(f"REGEXY: {func_name}")
                #     regex_name.add(func_name)
                # if "\\x" in repr(str(cstr)):
                #     print(f"NONSENSE: {func_name}")
                if "\\x" in repr(str(cstr)):
                    print(f"      ⚠️ Skipping non-ascii string: {repr(str(cstr))[:40]}")
                    continue
                if str(cstr).startswith("/AppleInternal/Library/BuildRoots/"):
                    # print(f"      ⚠️ Skipping BuildRoots string: {repr(str(cstr))[:40]}")
                    print(f"      ⚠️ Skipping BuildRoots string: {repr(str(cstr))}")
                    continue

                func_name = idc.get_func_name(xrefs[0])
                if func_name:
                    unique_function_names.add(func_name)
                    unique_symbols.add(func_name)

                if func_name not in sigs:
                    if func_name.startswith("sub_F"):
                        continue  # Skip unnamed functions
                    # func_name = func_name.removesuffix("_0")  # IDA Pro adds _0 on duplicate function names
                    to_chains, from_chains = get_unique_func_xref_chains(xrefs[0])
                    backtrace = []
                    if len(from_chains) == 1:
                        for chain in from_chains:
                            for ea in chain:
                                if idc.get_func_name(ea) == func_name:
                                    continue
                                print(f"  📚 adding FROM {func_name} backtrace {idc.get_func_name(ea)}")
                                print("😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱😱")
                                return
                    if len(to_chains) == 1:
                        for chain in to_chains:
                            for ea in chain:
                                # print(f"  📚 adding TO {func_name} backtrace {idc.get_func_name(ea)}")
                                fname = idc.get_func_name(ea)
                                backtrace.append(fname)
                                unique_backtrace_funcs.add(fname)
                                unique_symbols.add(fname)

                    sigs[func_name] = {"args": get_func_arg_count(xrefs[0]), "backtrace": backtrace, "anchors": []}

                # print(f"      📚 {func_name} -> {repr(str(cstr))[:40]}")
                trace = False
                if func_name == "":
                    trace = True
                caller = find_function_calling_string(xrefs[0], trace)
                if caller:
                    unique_anchor_caller.add(caller)
                    unique_symbols.add(caller)

                sigs[func_name]["anchors"].append(
                    {
                        "string": str(cstr),
                        "segment": segname,
                        "section": sectname,
                        "caller": caller,
                    }
                )
                # print(f'0x{xrefs[0]:x}: {func_name}(args: {args}) -> "{repr(s.content)}"')
    print("\n✅ Done ================================================================================\n")

    # Output unique function names
    print("[STATS]")
    print(f"\nUnique Function Names:   {len(unique_function_names)}")
    print(f"Unique Backtrace Names:  {len(unique_backtrace_funcs)}")
    print(f"Unique Anchor Caller:    {len(unique_anchor_caller)}")
    print("---------------------------")
    print(f"TOTAL UNIQUE SYMBOLS 🎉: {len(unique_symbols)}\n")
    print("=======================================================================================")
    # for func_name in sorted(unique_anchor_caller):
    # print(func_name)

    symctr = Symbolicator(
        target=os.getenv("TARGET", "com.apple.kernel"),
        total=len(unique_symbols),
        version=Version(
            os.getenv("MAX_VERSION", "24.0.0"),
            os.getenv("MIN_VERSION", "24.0.0"),
        ),
        signatures=[],
    )

    for func_name, sig in sigs.items():
        anchors = []
        for anchor in sig["anchors"]:
            anchors.append(
                Anchor(
                    string=anchor["string"],
                    segment=anchor["segment"],
                    section=anchor["section"],
                    caller=anchor["caller"],
                )
            )
        symctr.signatures.append(
            Signature(
                args=sig["args"],
                anchors=anchors,
                symbol=func_name,
                prototype="",
                backtrace=sig["backtrace"],
            )
        )

    if len(unique_symbols) > 0 or len(symctr.signatures):
        print(f"📝 Writing {len(symctr.signatures)} signatures to {sig_path}")
        symctr.write(sig_path)
    print("=======================================================================================")


if __name__ == "__main__":
    sig_path = os.getenv("JSON_FILE", "/tmp/signature.json")
    if not sig_path:
        print("=======================================================================================")
        print("❌ ERROR: 'JSON_FILE' environment variable not set")
        print("=======================================================================================")
        qexit(1)
    else:
        auto_mark_range(0, BADADDR, AU_FINAL)
        auto_wait()
        find_single_refs(sig_path)
    qexit(0)
