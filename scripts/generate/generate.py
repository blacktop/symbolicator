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
from collections import Counter, deque
from typing import Dict, Iterable, Optional

import ida_auto
import ida_funcs
import ida_pro
import ida_xref
import idaapi
import idautils
import idc
from idadex import ea_t
from macho import get_section_by_name

from symbolicator import Anchor, Signature, Symbolicator, Version


def resolve_text_range() -> tuple[int, int]:
    for segment, section in [("__TEXT_EXEC", "__text"), ("__TEXT", "__text")]:
        start, end = get_section_by_name(segment, section)
        if start is not None and end is not None:
            return start, end

    print("⚠️ Could not locate __text section; falling back to the full address space")
    return 0, idaapi.BADADDR


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
    if start is None or end is None:
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


# Callee names that are more useful for disambiguation (ranked by priority)
INTERESTING_CALLEES = [
    "panic",
    "assert",
    "kprintf",
    "printf",
    "os_log",
    "abort",
    "IOLog",
    "OSKext",
]


def rank_callee(name: str) -> int:
    """Return priority score for a callee name (lower is better)."""
    if not name:
        return 999
    name_lower = name.lower()
    for i, pattern in enumerate(INTERESTING_CALLEES):
        if pattern.lower() in name_lower:
            return i
    # Prefer named functions over sub_* (which shouldn't appear, but safety check)
    if name.startswith("sub_"):
        return 998
    return 100  # Default priority for other named functions


def find_block_containing(fc, ea):
    """Find the basic block containing the given address."""
    for block in fc:
        if block.start_ea <= ea < block.end_ea:
            return block
    return None


def get_block_callees(block, func_start, func_end):
    """Get all callees from a basic block."""
    callees = []
    for head in idautils.Heads(block.start_ea, block.end_ea):
        callee_start = get_instruction_callee_start(head, func_start, func_end)
        if callee_start == idc.BADADDR:
            continue
        callee_name = idc.get_func_name(callee_start)
        if callee_name and callee_name not in callees:
            callees.append(callee_name)
    return callees


def get_instruction_callee_start(head, func_start, func_end):
    """Resolve the callee start for a call or tail-call style instruction."""
    mnem = idc.print_insn_mnem(head)
    if mnem == "BL":
        target = idc.get_operand_value(head, 0)
        if target and target != idc.BADADDR:
            callee_func = idaapi.get_func(target)
            if callee_func:
                return callee_func.start_ea
    elif mnem in [
        "BLR",
        "BLRAA",
        "BLRAAZ",
        "BLRAB",
        "BLRABZ",
        "BR",
        "BRAA",
        "BRAAZ",
        "BRAB",
        "BRABZ",
    ]:
        reg = idc.print_operand(head, 0)
        target = track_register_value(head, reg, func_start)
        if target != idc.BADADDR:
            callee_func = idaapi.get_func(target)
            if callee_func:
                return callee_func.start_ea
    elif mnem == "B":
        target = idc.get_operand_value(head, 0)
        if target and target != idc.BADADDR and (target < func_start or target >= func_end):
            callee_func = idaapi.get_func(target)
            if callee_func:
                return callee_func.start_ea
    return idc.BADADDR


def find_function_calling_string(string_ref_addr):
    """Find the most relevant callee from a function that references a string.

    Uses FlowChart to walk basic blocks starting from the block containing
    the string reference, collecting all callees and ranking by importance.
    """
    func = ida_funcs.get_func(string_ref_addr)
    if not func:
        return None

    try:
        fc = idaapi.FlowChart(func)
    except Exception:
        return None

    # Find the block containing the string reference
    start_block = find_block_containing(fc, string_ref_addr)
    if not start_block:
        return None

    # BFS through basic blocks to find callees
    callees = []
    visited_blocks = set()
    max_depth = int(os.getenv("MAX_CALLEE_SEARCH_DEPTH", "8"))
    block_queue = deque([(start_block, 0)])

    while block_queue:
        block, depth = block_queue.popleft()
        if block.id in visited_blocks:
            continue
        visited_blocks.add(block.id)

        # Get callees from this block
        block_callees = get_block_callees(block, func.start_ea, func.end_ea)
        for callee in block_callees:
            if callee not in callees:
                callees.append(callee)

        # Add successor blocks to queue with a real depth bound.
        if depth < max_depth:
            for succ in block.succs():
                if succ.id not in visited_blocks:
                    block_queue.append((succ, depth + 1))

    if not callees:
        return None

    # Rank callees and return the most interesting one
    callees.sort(key=rank_callee)
    return callees[0]


def track_register_value(start_addr, reg, func_start):
    """Track register value backwards to find the source address.

    Handles ADRP+ADD pairs, ADR, MOV, LDR literal, and MOVZ+MOVK chains.
    """
    curr_addr = start_addr
    while curr_addr >= func_start:
        curr_addr = idc.prev_head(curr_addr, func_start)
        if curr_addr == idc.BADADDR:
            break
        mnem = idc.print_insn_mnem(curr_addr)
        if mnem == "ADRP":
            if idc.print_operand(curr_addr, 0) == reg:
                base = idc.get_operand_value(curr_addr, 1)
                # Look for ADD/LDR that uses this page base
                next_addr = idc.next_head(curr_addr)
                while next_addr < start_addr:
                    next_mnem = idc.print_insn_mnem(next_addr)
                    if idc.print_operand(next_addr, 0) == reg:
                        if next_mnem == "ADD":
                            offset = idc.get_operand_value(next_addr, 2)
                            return base + offset
                        elif next_mnem == "LDR":
                            # ADRP + LDR pair - IDA's get_operand_value on memory operand
                            # returns the computed address including scale
                            mem_addr = idc.get_operand_value(next_addr, 1)
                            if mem_addr and mem_addr != idc.BADADDR:
                                return mem_addr
                            # Fallback: manual calculation with page offset
                            # Note: this may not account for all access sizes
                            return base + (idc.get_operand_value(next_addr, 1) & 0xFFF)
                        break
                    next_addr = idc.next_head(next_addr)
                return idc.BADADDR  # No matching ADD/LDR - half-resolved page is unreliable
        elif mnem == "ADR":
            if idc.print_operand(curr_addr, 0) == reg:
                return idc.get_operand_value(curr_addr, 1)
        elif mnem == "MOVZ":
            if idc.print_operand(curr_addr, 0) == reg:
                # Start accumulating MOVZ/MOVK chain
                # IDA's get_operand_value returns the already-shifted immediate
                value = idc.get_operand_value(curr_addr, 1)
                # Look forward for MOVK instructions
                next_addr = idc.next_head(curr_addr)
                while next_addr < start_addr:
                    next_mnem = idc.print_insn_mnem(next_addr)
                    if next_mnem == "MOVK" and idc.print_operand(next_addr, 0) == reg:
                        # IDA's get_operand_value already returns shifted value
                        # We OR it directly into the accumulator
                        imm = idc.get_operand_value(next_addr, 1)
                        value |= imm
                    elif idc.print_operand(next_addr, 0) == reg:
                        # Register is overwritten by something else
                        break
                    next_addr = idc.next_head(next_addr)
                return value
        elif mnem == "MOV":
            if idc.print_operand(curr_addr, 0) == reg:
                return idc.get_operand_value(curr_addr, 1)
        elif mnem == "LDR":
            # Handle LDR from literal pool
            if idc.print_operand(curr_addr, 0) == reg:
                op_type = idc.get_operand_type(curr_addr, 1)
                if op_type == idc.o_mem:  # Memory reference (literal pool)
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


def get_function_callers(func_start_ea):
    callers = []
    seen = set()
    for xref_ea in idautils.CodeRefsTo(func_start_ea, 0):
        caller_func = idaapi.get_func(xref_ea)
        if not caller_func:
            continue
        caller_start = caller_func.start_ea
        if caller_start in seen:
            continue
        seen.add(caller_start)
        callers.append(caller_start)
    return callers


def get_named_function_callers(func_start_ea):
    caller_names = set()
    for caller_start in get_function_callers(func_start_ea):
        caller_name = idc.get_func_name(caller_start)
        if caller_name and not caller_name.startswith("sub_"):
            caller_names.add(caller_name)
    return caller_names


def get_function_callees(func):
    callees = []
    seen = set()
    for head in idautils.FuncItems(func.start_ea):
        callee_start = get_instruction_callee_start(head, func.start_ea, func.end_ea)
        if callee_start == idc.BADADDR or callee_start in seen:
            continue
        seen.add(callee_start)
        callees.append(callee_start)
    return callees


def get_function_callees_from_start(func_start_ea):
    func = idaapi.get_func(func_start_ea)
    if not func:
        return []
    return get_function_callees(func)


def get_unique_func_xref_chains(ea):
    func = idaapi.get_func(ea)
    if not func:
        print(f"No function found at address 0x{ea:X}")
        return [], []

    def follow_chain(start_ea, get_xrefs_func):
        chain = [start_ea]
        current_ea = start_ea
        while True:
            next_funcs = list(get_xrefs_func(current_ea))
            if len(next_funcs) != 1:
                break
            next_ea = next_funcs[0]
            if next_ea in chain:  # Avoid cycles
                break
            chain.append(next_ea)
            current_ea = next_ea
        return chain

    # Get xref chains to the function
    to_chains = []
    for caller_start in get_function_callers(func.start_ea):
        chain = follow_chain(caller_start, get_function_callers)
        to_chains.append(list(chain))

    # Get xref chains from the function
    from_chains = []
    for callee_start in get_function_callees(func):
        if callee_start not in [chain[0] for chain in from_chains]:
            callee_func = idaapi.get_func(callee_start)
            if not callee_func:
                continue
            chain = follow_chain(callee_start, get_function_callees_from_start)
            from_chains.append(list(reversed(chain)))

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


def build_string_index(sections, seg_start, seg_end):
    """Build an index of all strings (including non-unique) → set of referencing functions.

    Uses a single pass over Strings() and deduplicates entries.
    Returns (string_to_funcs, func_to_strings, string_func_counts)
    """
    # Build section ranges for fast lookup
    section_ranges = {}
    for segname, sectname in sections:
        start, end = get_section_by_name(segname, sectname)
        if start is not None and end is not None:
            section_ranges[(segname, sectname)] = (start, end)

    if not section_ranges:
        return {}, {}, {}

    string_to_funcs = {}  # string content → list of (func_name, xref_ea, string_ea, segment, section)
    func_to_strings = {}  # func_name → set of string contents
    string_func_sets = {}  # string content → set of function names (for frequency)
    seen_pairs = set()  # (string_ea, func_ea) for dedup

    # Single pass over all strings
    for string in idautils.Strings():
        string_ea = string.ea

        # Find which section this string belongs to
        section_info = None
        for (segname, sectname), (start, end) in section_ranges.items():
            if start <= string_ea < end:
                section_info = (segname, sectname)
                break

        if not section_info:
            continue

        string_content = str(string)
        # Skip problematic strings
        if "\\x" in repr(string_content):
            continue
        if string_content.startswith("/AppleInternal/Library/BuildRoots/"):
            continue

        xrefs = get_xrefs(string_ea)
        for xref_ea in xrefs:
            if xref_ea < seg_start or xref_ea > seg_end:
                continue

            # Dedup by (string_ea, xref_ea)
            pair_key = (string_ea, xref_ea)
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            func = ida_funcs.get_func(xref_ea)
            if not func:
                continue
            func_name = idc.get_func_name(func.start_ea)
            # Include sub_ for index purposes (filter at emit time)
            if not func_name:
                continue

            segname, sectname = section_info

            # Add to string_to_funcs
            if string_content not in string_to_funcs:
                string_to_funcs[string_content] = []
            string_to_funcs[string_content].append((func_name, xref_ea, string_ea, segname, sectname))

            # Add to func_to_strings
            if func_name not in func_to_strings:
                func_to_strings[func_name] = set()
            func_to_strings[func_name].add(string_content)

            # Track distinct function count per string
            if string_content not in string_func_sets:
                string_func_sets[string_content] = set()
            string_func_sets[string_content].add(func_name)

    string_func_counts = {s: len(funcs) for s, funcs in string_func_sets.items()}
    return string_to_funcs, func_to_strings, string_func_counts


def dual_evidence_disambiguation(
    labeled_funcs: set,
    sigs: dict,
    unique_symbols: set,
    string_to_funcs: dict,
    func_to_strings: dict,
) -> int:
    """Disambiguate non-unique strings using call-edge context.

    For each high-confidence callee H (from unique-string anchors), find its callers C.
    For each caller c in C, find strings that are unique within C (not globally unique,
    but appear in exactly one function among the callers of H).

    Returns the number of new signatures added.
    """
    new_sigs = 0

    # For each labeled function, find its callers
    for labeled_func in list(labeled_funcs):
        func_ea = idc.get_name_ea_simple(labeled_func)
        if func_ea == idc.BADADDR:
            continue

        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        # Get all callers of this labeled function
        callers = get_named_function_callers(func.start_ea)

        if len(callers) < 2:
            continue  # Need multiple callers for disambiguation to be useful

        # For each string referenced by any caller, check if it's unique among callers
        caller_strings = {}  # string → set of callers that reference it
        for caller in callers:
            if caller not in func_to_strings:
                continue
            for string_content in func_to_strings[caller]:
                if string_content not in caller_strings:
                    caller_strings[string_content] = set()
                caller_strings[string_content].add(caller)

        # Find strings unique within this caller set
        for string_content, referencing_callers in caller_strings.items():
            if len(referencing_callers) == 1:
                # This string is unique among callers of the labeled function
                caller_name = list(referencing_callers)[0]

                # Skip if already labeled with high confidence (direct or dual-evidence)
                # But allow upgrading propagated entries
                if caller_name in sigs:
                    existing_provenance = sigs[caller_name].get("provenance", "direct")
                    if existing_provenance != "propagated":
                        continue  # Already has strong evidence
                    # Will upgrade below

                # Get string metadata
                if string_content not in string_to_funcs:
                    continue

                for func_name, xref_ea, string_ea, segname, sectname in string_to_funcs[string_content]:
                    if func_name == caller_name:
                        # Skip sub_ at emit time
                        if caller_name.startswith("sub_"):
                            break
                        caller_ea = idc.get_name_ea_simple(caller_name)
                        new_anchor = {
                            "string": string_content,
                            "segment": segname,
                            "section": sectname,
                            "caller": labeled_func,  # Context: calls this labeled function
                        }
                        if caller_name in sigs:
                            # Upgrade existing propagated entry
                            sigs[caller_name]["anchors"].append(new_anchor)
                            sigs[caller_name]["provenance"] = "dual-evidence"
                        else:
                            # Create new signature with dual-evidence anchor
                            sigs[caller_name] = {
                                "args": get_func_arg_count(caller_ea),
                                "backtrace": [],
                                "anchors": [new_anchor],
                                "provenance": "dual-evidence",
                            }
                        unique_symbols.add(caller_name)
                        new_sigs += 1
                        break

    return new_sigs


def weak_string_callee_seeding(
    labeled_funcs: set,
    sigs: dict,
    unique_symbols: set,
    string_to_funcs: dict,
    func_to_strings: dict,
    string_func_counts: dict,
    max_freq: int = 3,
    allow_upgrade: bool = False,
) -> tuple[int, dict]:
    """Seed new symbols using moderately-unique strings plus a known labeled callee.

    If a function calls any labeled function and references a string that appears
    in ≤ max_freq functions globally, emit/upgrade it with provenance "weak-string+callee".
    """
    new_sigs = 0
    stats = {
        "candidates": 0,
        "with_strings_leq_freq": 0,
        "with_labeled_callee": 0,
        "upgraded": 0,
    }
    labeled_set = set(labeled_funcs)

    for func_name, strings in func_to_strings.items():
        stats["candidates"] += 1

        # Skip strong labels unless upgrades are allowed
        if func_name in sigs and not allow_upgrade:
            if sigs[func_name].get("provenance", "direct") not in ["propagated"]:
                continue

        # Collect moderately-unique strings in this function
        candidate_strings = [s for s in strings if string_func_counts.get(s, 0) <= max_freq]
        if not candidate_strings:
            continue
        stats["with_strings_leq_freq"] += 1

        func_ea = idc.get_name_ea_simple(func_name)
        if func_ea == idc.BADADDR:
            continue
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        # Does this function call any labeled function?
        callee_hit = None
        for head in idautils.FuncItems(func.start_ea):
            for xref in idautils.XrefsFrom(head, 0):
                if xref.type not in [ida_xref.fl_CN, ida_xref.fl_CF]:
                    continue
                callee_func = ida_funcs.get_func(xref.to)
                if not callee_func:
                    continue
                callee_name = idc.get_func_name(callee_func.start_ea)
                if callee_name in labeled_set:
                    callee_hit = callee_name
                    break
            if callee_hit:
                break

        if not callee_hit:
            continue
        stats["with_labeled_callee"] += 1

        # Anchor with the first candidate string
        anchor_string = candidate_strings[0]
        # Retrieve segment/section metadata
        meta_list = string_to_funcs.get(anchor_string, [])
        segname = sectname = None
        for fname, _, _, seg, sect in meta_list:
            if fname == func_name:
                segname, sectname = seg, sect
                break
        if not segname:
            continue

        new_anchor = {
            "string": anchor_string,
            "segment": segname,
            "section": sectname,
            "caller": callee_hit,
        }

        if func_name in sigs:
            sigs[func_name]["anchors"].append(new_anchor)
            sigs[func_name]["provenance"] = "weak-string+callee"
            stats["upgraded"] += 1
        else:
            sigs[func_name] = {
                "args": get_func_arg_count(func_ea),
                "backtrace": [],
                "anchors": [new_anchor],
                "provenance": "weak-string+callee",
            }
        unique_symbols.add(func_name)
        new_sigs += 1

    stats["produced"] = new_sigs
    return new_sigs, stats


def propagate_labels_bfs(labeled_funcs: set, sigs: dict, unique_symbols: set) -> int:
    """BFS propagation through degree-1 call chains.

    For each labeled function:
    - If it has exactly one caller that's unlabeled, propagate up
    - If it has exactly one callee that's unlabeled, propagate down

    Propagated labels are tagged with provenance="propagated" to indicate
    lower confidence than direct anchor-based labels.

    Returns the number of new labels added.
    """
    new_labels = 0
    queue = deque(labeled_funcs)
    visited = set(labeled_funcs)

    while queue:
        func_name = queue.popleft()

        # Get the function address from the name
        func_ea = idc.get_name_ea_simple(func_name)
        if func_ea == idc.BADADDR:
            continue

        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        # Check for single caller (propagate up)
        caller_funcs = get_named_function_callers(func.start_ea)

        if len(caller_funcs) == 1:
            caller_name = list(caller_funcs)[0]
            if caller_name not in visited:
                visited.add(caller_name)
                unique_symbols.add(caller_name)
                new_labels += 1
                queue.append(caller_name)
                # Add to sigs if not present (with provenance tag)
                if caller_name not in sigs:
                    caller_ea = idc.get_name_ea_simple(caller_name)
                    sigs[caller_name] = {
                        "args": get_func_arg_count(caller_ea),
                        "backtrace": [func_name],  # The function we propagated from
                        "anchors": [],
                        "provenance": "propagated",
                    }

        # Check for single callee (propagate down)
        callees = set()
        for callee_start in get_function_callees(func):
            callee_name = idc.get_func_name(callee_start)
            if callee_name and not callee_name.startswith("sub_"):
                callees.add(callee_name)

        if len(callees) == 1:
            callee_name = list(callees)[0]
            if callee_name not in visited:
                visited.add(callee_name)
                unique_symbols.add(callee_name)
                new_labels += 1
                queue.append(callee_name)
                # Add to sigs if not present (with provenance tag)
                if callee_name not in sigs:
                    callee_ea = idc.get_name_ea_simple(callee_name)
                    sigs[callee_name] = {
                        "args": get_func_arg_count(callee_ea),
                        "backtrace": [func_name],  # The function we propagated from
                        "anchors": [],
                        "provenance": "propagated",
                    }

    return new_labels


# Usage: Call this function with the address of the function you want to analyze
# For example: get_unique_xref_chains(0x1400010A0)
def find_single_refs(sig_path: str) -> None:
    seg_start, seg_end = resolve_text_range()
    unique_function_names = set()
    unique_anchor_caller = set()
    unique_backtrace_funcs = set()
    unique_symbols = set()

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
                    if not func_name or func_name.startswith("sub_F"):
                        continue  # Skip unnamed/auto-generated functions
                    to_chains, from_chains = get_unique_func_xref_chains(xrefs[0])
                    backtrace = []
                    if len(from_chains) == 1:
                        for chain in from_chains:
                            for ea in chain:
                                fname = idc.get_func_name(ea)
                                if fname == func_name:
                                    continue
                                backtrace.append(fname)
                                unique_backtrace_funcs.add(fname)
                                unique_symbols.add(fname)
                    if len(to_chains) == 1:
                        for chain in to_chains:
                            for ea in chain:
                                fname = idc.get_func_name(ea)
                                backtrace.append(fname)
                                unique_backtrace_funcs.add(fname)
                                unique_symbols.add(fname)

                    sigs[func_name] = {
                        "args": get_func_arg_count(xrefs[0]),
                        "backtrace": backtrace,
                        "anchors": [],
                    }

                caller = find_function_calling_string(xrefs[0])
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

    # Build string index for dual-evidence / weak-string processing
    print("📇 Building string index for dual-evidence disambiguation...")
    string_to_funcs, func_to_strings, string_func_counts = build_string_index(sections, seg_start, seg_end)
    print(f"    📊 Indexed {len(string_to_funcs)} strings across {len(func_to_strings)} functions")

    # BFS propagation through degree-1 call chains
    print("🔗 Propagating labels through degree-1 call chains...")
    propagated = propagate_labels_bfs(set(sigs.keys()), sigs, unique_symbols)
    print(f"    📈 Added {propagated} symbols via call-graph propagation")

    # Dual-evidence disambiguation for non-unique strings
    print("🔍 Running dual-evidence string disambiguation...")
    disambiguated = dual_evidence_disambiguation(
        set(sigs.keys()), sigs, unique_symbols, string_to_funcs, func_to_strings
    )
    print(f"    📈 Added {disambiguated} symbols via dual-evidence disambiguation")

    # Weak-string + known callee seeding
    weak_max = int(os.getenv("WEAK_STRING_MAX_FREQ", "5"))  # Conservative default
    allow_weak_upgrade = os.getenv("ALLOW_WEAK_UPGRADE", "0") == "1"  # Off by default
    print(f"🧩 Running weak-string+callee seeding (freq ≤ {weak_max}, allow_upgrade={allow_weak_upgrade})...")
    weak_added, weak_stats = weak_string_callee_seeding(
        set(sigs.keys()),
        sigs,
        unique_symbols,
        string_to_funcs,
        func_to_strings,
        string_func_counts,
        weak_max,
        allow_weak_upgrade,
    )
    print(f"    📈 Added {weak_added} symbols via weak-string+callee seeding")
    print(
        f"    ℹ️ Candidates: {weak_stats.get('candidates', 0)}, "
        f"with <=freq strings: {weak_stats.get('with_strings_leq_freq', 0)}, "
        f"with labeled callee: {weak_stats.get('with_labeled_callee', 0)}, "
        f"upgraded: {weak_stats.get('upgraded', 0)}"
    )

    # Filter signatures: emit those with anchors OR propagated with backtrace
    # Pure propagated signatures without ANY evidence are skipped
    emitted_sigs = []
    skipped_propagated = 0

    for func_name, sig in sigs.items():
        has_anchors = len(sig["anchors"]) > 0
        has_backtrace = len(sig.get("backtrace", [])) > 0
        provenance = sig.get("provenance", "direct")

        # Skip propagated signatures without anchors AND without backtrace
        if provenance == "propagated" and not has_anchors and not has_backtrace:
            skipped_propagated += 1
            continue

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
        emitted_sigs.append(
            Signature(
                args=sig["args"],
                anchors=anchors,
                symbol=func_name,
                prototype="",
                backtrace=sig["backtrace"],
                provenance=provenance,
            )
        )

    # Output stats based on what will actually be emitted
    print("\n[STATS]")
    print(f"\nUnique Function Names:   {len(unique_function_names)}")
    print(f"Unique Backtrace Names:  {len(unique_backtrace_funcs)}")
    print(f"Unique Anchor Caller:    {len(unique_anchor_caller)}")
    print(f"Propagated Labels:       {propagated}")
    print(f"Dual-Evidence Labels:    {disambiguated}")
    print(f"Weak-String+Call Labels: {weak_added}")
    print(f"Skipped (no anchors/backtrace): {skipped_propagated}")
    print("---------------------------")
    print(f"EMITTED SIGNATURES 🎉:   {len(emitted_sigs)}\n")
    print("=======================================================================================")

    symctr = Symbolicator(
        target=os.getenv("TARGET", "com.apple.kernel"),
        total=len(unique_symbols),
        version=Version(
            os.getenv("MAX_VERSION", "24.0.0"),
            os.getenv("MIN_VERSION", "24.0.0"),
        ),
        signatures=emitted_sigs,
    )

    if len(symctr.signatures) > 0:
        print(f"📝 Writing {len(symctr.signatures)} signatures to {sig_path}")
        symctr.write(sig_path)
    print("=======================================================================================")


if __name__ == "__main__":
    sig_path = os.getenv("JSON_FILE", "/tmp/signature.json")
    if not sig_path:
        print("=======================================================================================")
        print("❌ ERROR: 'JSON_FILE' environment variable not set")
        print("=======================================================================================")
        ida_pro.qexit(1)
    else:
        ida_auto.auto_mark_range(0, idaapi.BADADDR, ida_auto.AU_FINAL)
        ida_auto.auto_wait()
        find_single_refs(sig_path)
    ida_pro.qexit(0)
