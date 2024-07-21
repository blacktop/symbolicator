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

import idaapi
import idc


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
            try:
                with open(file_path, "r") as file:
                    data = json.load(file)
                    self.process_symbol_map(data)
            except Exception as e:
                print(f"Failed to load symbol map JSON file: {e}")
        else:
            print("No file selected.")

    def process_symbol_map(self, data):
        # Process the symbol map JSON data
        addr2sym = json.dumps(data, indent=4)
        count = 0
        for addr, sym in data.items():
            print(f"[Symbolicated] 0x{int(addr, 10):x}: {sym}")
            idc.set_name(int(addr, 10), sym, idc.SN_NOWARN)
            count += 1
        print(f"🎉 Symbolicated {count} addresses 🎉")

    def term(self):
        pass
        # print("Symbolicate Plugin terminated.")


def PLUGIN_ENTRY():
    return SymbolicatePlugin()
