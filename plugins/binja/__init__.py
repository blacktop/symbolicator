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
from binaryninja import BinaryView, Logger


def run(bv):
    log = bv.create_logger("Plugin.Symbolicate")
    json_file_path = get_open_filename_input("Select JSON file")
    if not json_file_path:
        log.log_info("No file selected. Exiting.")
        return

    try:
        with open(json_file_path, "r") as f:
            symbols = json.load(f)
    except Exception as e:
        log.log_error(f"Error reading JSON file: {str(e)}")
        return
    apply_symbols_and_create_functions(bv=bv, log=log, symbols=symbols)


def apply_symbols_and_create_functions(bv: BinaryView, log: Logger, symbols: dict):
    count = 0
    for address_str, symbol_name in symbols.items():
        try:
            # Convert address string to int
            address = int(address_str, 10)
            # Ensure the address is valid
            if address < bv.start or address >= bv.end:
                log.log_info(f"Address {hex(address)} is out of range for this binary")
                continue
            # Create a function if it doesn't exist
            if not bv.get_function_at(address):
                bv.create_user_function(address)
                log.log_info(f"Created function at address {hex(address)}")
            # Get the function
            func = bv.get_function_at(address)
            if func:
                # Set the function name (which also creates the symbol)
                func.name = symbol_name
                # log.log_info(f"Applied symbol and set function name: {symbol_name} at address {hex(address)}")
                log.log_debug(f"[Symbolicated] 0x{hex(address)}: {symbol_name}")
            else:
                log.log_error(f"Failed to create or get function at address {hex(address)}")
            count += 1
        except ValueError:
            log.log_error(f"Error parsing address: {address_str}")
        except Exception as e:
            log.log_error(f"Error processing symbol: {symbol_name} at {address_str} - {str(e)}")
    log.log_info(f"🎉 Symbolicated {count} addresses 🎉")


def is_valid(bv: BinaryView) -> bool:
    bv.create_logger("Plugin.Symbolicate")
    return True


PluginCommand.register("`ipsw` Symbolicate Plugin", "Symbolicate kernelcache with symbols.json", run, is_valid)
