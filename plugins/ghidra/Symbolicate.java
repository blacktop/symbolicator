//Imports `ipsw` symbols.json files into Project creating functions (if they don't exist) and adding symbols.
//@author blacktop
//@category iOS
//@keybinding 
//@menupath 
//@toolbar 

// MIT License
//
// Copyright (c) 2024 blacktop
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Function;

public class Symbolicate extends GhidraScript {

    @Override
    public void run() throws Exception {
        File jsonFile = askFile("Select symbols JSON file", "Open");
        Map<String, String> symbolsMap = parseJsonFile(jsonFile);
        applySymbolsAndCreateFunctions(symbolsMap);
    }

    private Map<String, String> parseJsonFile(File file) throws IOException {
        Gson gson = new Gson();
        Type type = new TypeToken<Map<String, String>>() {
        }.getType();

        try (FileReader reader = new FileReader(file)) {
            return gson.fromJson(reader, type);
        }
    }

    private void applySymbolsAndCreateFunctions(Map<String, String> symbolsMap) throws Exception {
        Program program = getCurrentProgram();
        FunctionManager functionManager = program.getFunctionManager();
        int successCount = 0; // Initialize the success count

        for (Map.Entry<String, String> entry : symbolsMap.entrySet()) {
            String addressString = entry.getKey();
            String symbolName = entry.getValue();

            try {
                // Convert address string to long
                long addressValue = Long.parseUnsignedLong(addressString, 10);
                Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(addressValue);

                // Check if address is valid
                if (!program.getMemory().contains(address)) {
                    println("Error: Address " + address + " is not valid for this program");
                    continue;
                }

                // Create function if it doesn't exist
                Function function = functionManager.getFunctionAt(address);
                if (function == null) {
                    function = functionManager.createFunction(null, address, null, SourceType.USER_DEFINED);
                    if (function == null) {
                        println("Error: Failed to create function at address " + address);
                        continue;
                    }
                    println("Created function at address " + address);
                }

                // Set function name (which also creates the symbol)
                function.setName(symbolName, SourceType.USER_DEFINED);
                println("Applied symbol and set function name: " + symbolName + " at address " + address);
                // Increment success count
                successCount++;
            } catch (NumberFormatException e) {
                println("Error parsing address: " + addressString + " - " + e.getMessage());
            } catch (Exception e) {
                println("Error processing symbol: " + symbolName + " at " + addressString + " - " + e.getMessage());
            }
        }

        println(String.format("🎉 Symbolicated %d addresses 🎉", successCount));
    }
}
