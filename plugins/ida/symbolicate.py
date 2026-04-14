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
from pathlib import Path

import ida_bytes
import ida_funcs
import ida_loader
import ida_name
import idaapi

SYMBOLS_LOADED_INDICATION = ".symbols_loaded"


class SymbolicatePlugin(idaapi.plugin_t):
    flags = 0
    comment = "Symbolicate Plugin"
    help = "This plugin prompts the user for a symbol map JSON file and processes it."
    wanted_name = "'ipsw' Symbolicate Plugin"
    wanted_hotkey = "Alt-F8"

    def init(self):
        print("Symbolicate Plugin initialized.")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        file_path = idaapi.ask_file(0, "*.json", "Select a symbol map JSON file")
        if file_path:
            self.process_json_file(file_path)
        else:
            print("No file selected.")

    def process_json_file(self, file_path: str) -> None:
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                data = json.load(file)
                self.process_symbol_map(data)
        except Exception as e:
            print(f"Failed to load symbol map JSON file: {e}")

    def process_symbol_map(self, addr2sym):
        func_count = 0
        data_count = 0
        skipped = 0
        failed = 0
        name_flags = ida_name.SN_NOCHECK | ida_name.SN_FORCE
        for addr_str, sym in addr2sym.items():
            addr = int(addr_str, 10)
            if addr == 0:
                skipped += 1
                continue
            if not idaapi.is_loaded(addr):
                skipped += 1
                continue

            is_func = ida_bytes.is_code(ida_bytes.get_flags(addr))
            if is_func and not ida_funcs.get_func(addr):
                ida_funcs.add_func(addr)

            if ida_name.set_name(addr, sym, name_flags):
                if is_func:
                    func_count += 1
                else:
                    data_count += 1
            else:
                failed += 1

        print(
            f"Symbolicated {func_count} functions "
            f"and {data_count} data symbols "
            f"({skipped} skipped, {failed} failed)"
        )

    def term(self):
        pass


def PLUGIN_ENTRY():
    result = SymbolicatePlugin()
    bin_file = ida_loader.get_path(ida_loader.PATH_TYPE_CMD)
    json_file = Path(bin_file + ".symbols.json")
    symbols_loaded_indication_file = Path(bin_file + SYMBOLS_LOADED_INDICATION)
    if json_file.exists() and not symbols_loaded_indication_file.exists():
        result.process_json_file(str(json_file))
        # indicate that symbols were already loaded so don't force reload
        # every time
        symbols_loaded_indication_file.touch()
    return result
