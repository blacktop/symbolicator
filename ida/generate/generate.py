# -*- coding: utf-8 -*-

import os
from collections import Counter
from typing import Iterable, Optional

import ida_funcs
import ida_idp
import ida_ua
import ida_idaapi
import ida_xref
import idautils
import idc
from idadex import ea_t

from macho import get_section_by_name
from symbolicator import Symbolicator, Anchor, Signature, Version


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
    while next_ea != ida_idaapi.BADADDR:
        xrefs.append(next_ea)
        next_ea = ida_xref.get_next_dref_to(ea, next_ea)
    return xrefs


def get_caller(start_ea: ea_t):
    loaded_register = None
    string_value = None
    ea = start_ea

    # print(f"👀👀👀 Look for caller using string at 0x{start_ea:x}")
    end_ea = idc.get_func_attr(start_ea, idc.FUNCATTR_END)

    insn = ida_ua.insn_t()
    if not ida_ua.decode_insn(insn, ea):
        # Failed to decode instruction
        return None

    if insn.get_canon_mnem() != "ADRL":
        return None

    # print("FOUND ADRL")

    # Check if the instruction loads a string into a register
    # https://hex-rays.com/products/ida/support/idapython_docs/ida_ua.html#ida_ua.op_t
    if insn.ops[1].type == idc.o_imm:
        str_ea = insn.ops[1].value
        string_value = idc.get_strlit_contents(str_ea)
        if string_value:
            loaded_register = insn.ops[0].reg
            # print(f"String '{string_value.decode()}' loaded into {ida_idp.get_reg_name(loaded_register, 8)} at {ea:#x}")

    ea = idc.next_head(ea, end_ea)
    if not ida_ua.decode_insn(insn, ea):
        # Failed to decode instruction
        return None

    if insn.get_canon_mnem() != "BL":
        return None

    # print("🎉 FOUND BL")

    if insn.ops[0].type == idc.o_near:
        caller_ea = insn.ops[0].addr
        # print(f"Caller address: {caller_ea:#x}")
        caller_name = idc.get_func_name(caller_ea)
        # print(f"Caller name: {caller_name}")
        return caller_name

    return None
    # while ea < end_ea:
    #     if not ida_ua.decode_insn(insn, ea):
    #         # Failed to decode instruction
    #         break

    #     # Check if the instruction is a call and uses the loaded register
    #     if insn.itype == idaapi.NN_call and loaded_register is not None:
    #         print("FOUND CALL INSTRUCTION AFTER ADRL")
    #         if insn.ops[0].type == idaapi.o_reg and insn.ops[0].reg == loaded_register:
    #             called_func_ea = insn.ops[0].addr
    #             func_name = idc.get_func_name(called_func_ea)
    #             print(
    #                 f"Function {func_name} called using register {idc.get_reg_name(loaded_register, 4)} after loading string '{string_value.decode()}' at {ea:#x}"
    #             )
    #             return func_name

    #     ea = idc.next_head(ea, end_ea)
    #     print(f"Next head: {ea:#x}")

    # print("No function call found after string load")
    # return None


def get_single_ref_funcs() -> {}:
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


def find_single_refs(sig_path: str) -> None:
    seg_start, seg_end = get_section_by_name("__TEXT_EXEC", "__text")
    unique_function_names = set()
    unique_anchor_caller = set()
    unique_backtrace_funcs = set()
    unique_symbols = set()

    sigs = {}
    single_ref_funcs = get_single_ref_funcs()
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
                if "\\x" in repr(str(cstr)):
                    print(f"      ⚠️ Skipping non-ascii string: {repr(str(cstr))[:40]}")
                    continue
                if str(cstr).startswith("/AppleInternal/Library/BuildRoots/"):
                    print(f"      ⚠️ Skipping BuildRoots string: {repr(str(cstr))[:40]}")
                    continue
                if xrefs[0] < seg_start or xrefs[0] > seg_end:
                    continue
                func_name = idc.get_func_name(xrefs[0])
                if func_name.startswith("sub_F"):
                    continue  # Skip unnamed functions
                # if str(cstr).startswith("/AppleInternal/Library/BuildRoots/"):
                #     print(f"REGEXY: {func_name}")
                # if "\\x" in repr(str(cstr)):
                #     print(f"NONSENSE: {func_name}")
                args = get_func_arg_count(xrefs[0])
                caller = get_caller(xrefs[0])
                if caller:
                    unique_anchor_caller.add(caller)
                    unique_symbols.add(caller)
                backtrace = []
                fname = func_name
                while fname in single_ref_funcs:
                    backtrace.append(single_ref_funcs[fname])
                    unique_backtrace_funcs.add(fname)
                    unique_symbols.add(single_ref_funcs[fname])
                    fname = single_ref_funcs[fname]
                if func_name:
                    unique_function_names.add(func_name)
                    unique_symbols.add(func_name)
                if func_name not in sigs:
                    sigs[func_name] = {
                        "args": args,
                        "backtrace": backtrace,
                        "anchors": [],
                    }
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
    # for func_name in sorted(unique_caller_names):
    #     print(func_name)

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
