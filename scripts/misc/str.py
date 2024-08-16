import ida_bytes
import ida_funcs
import ida_xref
import idautils
import idc


def get_string_at_address(address):
    # Determine the string type
    string_type = ida_bytes.get_str_type(address)

    if string_type == -1:  # No string type detected
        return None

    # Get the string length
    length = ida_bytes.get_max_strlit_length(address, string_type, ida_bytes.ALOPT_IGNHEADS)

    if length == 0:
        return None

    # Get the string contents
    string = ida_bytes.get_strlit_contents(address, length, string_type)

    # If the string is found, decode it from bytes to a Python string
    if string is not None:
        return string.decode("utf-8", errors="replace")
    else:
        return None


# Alternative simpler method using idc module
def get_string_at_address_simple(address):
    return idc.get_strlit_contents(address, -1, idc.STRTYPE_C)


def find_function_calling_string(curr_addr):
    func = ida_funcs.get_func(curr_addr)
    if not func:
        return None

    func_start = func.start_ea
    func_end = func.end_ea

    while func_start <= curr_addr < func_end:
        mnem = idc.print_insn_mnem(curr_addr)

        if mnem == "B":
            # Follow unconditional branch, but stay within function bounds
            target = idc.get_operand_value(curr_addr, 0)
            if func_start <= target < func_end:
                curr_addr = target
                continue
        elif mnem in ["BL", "BLR", "BR"]:
            if mnem == "BL":
                target = idc.get_operand_value(curr_addr, 0)
            elif mnem in ["BLR", "BR"]:
                reg = idc.print_operand(curr_addr, 0)
                target = track_register_value(curr_addr, reg, func_start)

            if target != idc.BADADDR:
                target_func = ida_funcs.get_func(target)
                if target_func:
                    print(f"Found function calling '{hex(curr_addr)}': {idc.get_func_name(target)}")
                    return target_func

        curr_addr = idc.next_head(curr_addr)

    print(f"No function found calling '{hex(curr_addr)}'")
    return None


def track_register_value(start_addr, reg):
    curr_addr = start_addr
    while curr_addr != idc.BADADDR:
        curr_addr = idc.prev_head(curr_addr)
        if idc.print_insn_mnem(curr_addr) == "ADRP":
            if idc.print_operand(curr_addr, 0) == reg:
                base = idc.get_operand_value(curr_addr, 1)
                # Look for following ADD instruction
                next_addr = idc.next_head(curr_addr)
                if idc.print_insn_mnem(next_addr) == "ADD" and idc.print_operand(next_addr, 0) == reg:
                    offset = idc.get_operand_value(next_addr, 2)
                    return base + offset
        elif idc.print_insn_mnem(curr_addr) in ["MOV", "MOVZ", "MOVK"]:
            if idc.print_operand(curr_addr, 0) == reg:
                return idc.get_operand_value(curr_addr, 1)
    return idc.BADADDR


find_function_calling_string(here())
