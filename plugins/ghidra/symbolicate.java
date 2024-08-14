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

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Function;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.FileReader;
import java.io.IOException;

public class Symbolicate extends GhidraScript {

    @Override
    public void run() throws Exception {
        String jsonFilePath = askString("Enter JSON file path", "Path to JSON file");
        JSONObject symbolsJson = parseJsonFile(jsonFilePath);
        applySymbolsAndCreateFunctions(symbolsJson);
    }

    private JSONObject parseJsonFile(String filePath) throws IOException {
        try (FileReader reader = new FileReader(filePath)) {
            JSONTokener tokener = new JSONTokener(reader);
            return new JSONObject(tokener);
        }
    }

    private void applySymbolsAndCreateFunctions(JSONObject symbolsJson) throws Exception {
        Program program = getCurrentProgram();
        FunctionManager functionManager = program.getFunctionManager();
        
        int transactionID = program.startTransaction("Import JSON Symbols");
        
        try {
            for (String addressString : symbolsJson.keySet()) {
                String symbolName = symbolsJson.getString(addressString);
                
                try {
                    // Convert address string to long
                    long addressValue = Long.parseLong(addressString);
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
                    
                } catch (NumberFormatException e) {
                    println("Error parsing address: " + addressString + " - " + e.getMessage());
                } catch (Exception e) {
                    println("Error processing symbol: " + symbolName + " at " + addressString + " - " + e.getMessage());
                }
            }
        } finally {
            program.endTransaction(transactionID, true);
        }
    }
}