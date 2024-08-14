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


def run(bv):
    json_file_path = get_open_filename_input("Select JSON file")
    if not json_file_path:
        log_info("No file selected. Exiting.")
        return

    try:
        with open(json_file_path, "r") as f:
            symbols_json = json.load(f)
    except Exception as e:
        log_error(f"Error reading JSON file: {str(e)}")
        return

    apply_symbols_and_create_functions(bv, symbols_json)


def apply_symbols_and_create_functions(bv, symbols_json):
    for address_str, symbol_name in symbols_json.items():
        try:
            # Convert address string to int
            address = int(address_str)

            # Ensure the address is valid
            if address < bv.start or address >= bv.end:
                log_error(f"Address {hex(address)} is out of range for this binary")
                continue

            # Create a function if it doesn't exist
            if not bv.get_function_at(address):
                bv.create_user_function(address)
                log_info(f"Created function at address {hex(address)}")

            # Get the function
            func = bv.get_function_at(address)
            if func:
                # Set the function name (which also creates the symbol)
                func.name = symbol_name
                log_info(f"Applied symbol and set function name: {symbol_name} at address {hex(address)}")
            else:
                log_error(f"Failed to create or get function at address {hex(address)}")

        except ValueError:
            log_error(f"Error parsing address: {address_str}")
        except Exception as e:
            log_error(f"Error processing symbol: {symbol_name} at {address_str} - {str(e)}")


PluginCommand.register("`ipsw` Symbolicate Plugin", "Symbolicate kernelcache with symbols.json", run)
