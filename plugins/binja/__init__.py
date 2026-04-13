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

import json
from binaryninja import *
from binaryninja import Architecture, BinaryView, Logger, PluginCommand, SectionSemantics, Symbol, SymbolType
from binaryninja.demangle import demangle_generic
from binaryninja.types import FunctionParameter, FunctionType, Type


def run(bv: BinaryView) -> None:
    log = bv.create_logger("Plugin.Symbolicate")
    json_file_path = get_open_filename_input("Select JSON file")
    if not json_file_path:
        log.log_info("No file selected. Exiting.")
        return

    try:
        with open(json_file_path, "r", encoding="utf-8") as f:
            symbols = json.load(f)
    except Exception as e:
        log.log_error(f"Error reading JSON file: {str(e)}")
        return
    apply_symbols_and_create_functions(bv=bv, log=log, symbols=symbols)


def is_executable_address(bv: BinaryView, address: int) -> bool:
    sections = bv.get_sections_at(address)
    for section in sections:
        if section.semantics == SectionSemantics.ReadOnlyCodeSectionSemantics:
            return True
    return False


def apply_symbols_and_create_functions(bv: BinaryView, log: Logger, symbols: dict[str, str]) -> None:
    func_count = 0
    data_count = 0
    arch = bv.arch
    assert arch is not None, "Architecture should be available for a kernelcache"
    for address_str, symbol_name in symbols.items():
        try:
            # Convert address string to int
            address = int(address_str, 10)
            # Ensure the address is valid
            if address < bv.start or address >= bv.end:
                log.log_info(f"Address {hex(address)} is out of range for this binary")
                continue

            demangled_name, func_type = demangle_symbol_if_mangled(symbol_name, arch)

            if is_executable_address(bv, address):
                if not bv.get_function_at(address):
                    bv.create_user_function(address)
                    log.log_info(f"Created function at address {hex(address)}")
                func = bv.get_function_at(address)
                if func:
                    func.name = demangled_name
                    if func_type is not None:
                        func.type = func_type
                    if demangled_name != symbol_name:
                        log.log_debug(f"[Symbolicated] {hex(address)}: {symbol_name} -> {demangled_name}")
                    else:
                        log.log_debug(f"[Symbolicated] {hex(address)}: {symbol_name}")
                    func_count += 1
                else:
                    log.log_error(f"Failed to create or get function at address {hex(address)}")
            else:
                bv.define_user_symbol(Symbol(SymbolType.DataSymbol, address, demangled_name))
                log.log_debug(f"[Data] {hex(address)}: {demangled_name}")
                data_count += 1
        except ValueError:
            log.log_error(f"Error parsing address: {address_str}")
        except Exception as e:
            log.log_error(f"Error processing symbol: {symbol_name} at {address_str} - {str(e)}")
    log.log_info(f"🎉 Symbolicated {func_count} functions and {data_count} data symbols 🎉")


def demangle_symbol_if_mangled(symbol_name: str, arch: Architecture) -> tuple[str, FunctionType | None]:
    if symbol_name.startswith("__Z"):
        demangle_result = demangle_generic(arch, symbol_name)
        if demangle_result is not None:
            type_signature, name_tokens = demangle_result
            demangled_name = "::".join(name_tokens)
            if isinstance(type_signature, FunctionType):
                # Check if this is a member function (has class::method pattern)
                # and add implicit 'this' pointer as first parameter
                if len(name_tokens) >= 2:
                    this_param = FunctionParameter(Type.pointer(arch, Type.void()), "this")
                    new_params = [this_param] + list(type_signature.parameters)
                    type_signature = Type.function(type_signature.return_value, new_params)
                return demangled_name, type_signature
            return demangled_name, None
    return symbol_name, None


def is_valid(bv: BinaryView) -> bool:
    bv.create_logger("Plugin.Symbolicate")
    return True


PluginCommand.register("`ipsw` Symbolicate Plugin", "Symbolicate kernelcache with symbols.json", run, is_valid)
