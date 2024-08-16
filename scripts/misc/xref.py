import idaapi
import idautils

print("Xrefs from here:")
for xref in idautils.XrefsFrom(here(), 0):
    print(xref.type, idautils.XrefTypeName(xref.type), "from", hex(xref.frm), "to", hex(xref.to))

print("Xrefs to here:")
for xref in idautils.XrefsTo(here(), 0):
    print(xref.type, idautils.XrefTypeName(xref.type), "from", hex(xref.frm), "to", hex(xref.to))
print()
for xref in idautils.CodeRefsTo(here(), 0):
    print("CodeRefsTo", hex(xref))
print()


def get_unique_function_xref_chain(start_func):
    def get_single_xref_func(func):
        xrefs = [xref.frm for xref in idautils.CodeRefsTo(func.start_ea, 0) if idaapi.get_func(xref.frm)]
        return idaapi.get_func(xrefs[0]) if len(xrefs) == 1 else None

    chain = []
    current_func = idaapi.get_func(start_func)

    while current_func:
        xref_func = get_single_xref_func(current_func)
        if not xref_func or xref_func.start_ea in chain:
            break
        chain.append(idaapi.get_func_name(xref_func.start_ea))
        current_func = xref_func

    return chain


# Example usage
start_func_addr = here()  # Get current address, replace with your desired function start address
xref_chain = get_unique_function_xref_chain(start_func_addr)

print("Unique function xref chain:")
for fn in xref_chain:
    print(fn)
