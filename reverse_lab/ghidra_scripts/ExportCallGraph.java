// @category ReverseLab
// Export statically resolved function-to-function calls as bounded JSON.
// Missing indirect/dynamic calls should NOT be interpreted as proof they do not exist.
import com.google.gson.stream.JsonWriter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class ExportCallGraph extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException("Expected output file, max callers and max edges");
        }
        int maxCallers = Integer.parseInt(args[1]);
        int maxEdges = Integer.parseInt(args[2]);
        if (maxCallers < 1 || maxCallers > 500 || maxEdges < 1 || maxEdges > 5000) {
            throw new IllegalArgumentException("Call graph limits out of range");
        }

        try (JsonWriter writer = new JsonWriter(
                Files.newBufferedWriter(Paths.get(args[0]), StandardCharsets.UTF_8))) {
            writer.beginArray();
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            int callers = 0;
            int edges = 0;
            while (iterator.hasNext() && !monitor.isCancelled() &&
                   callers < maxCallers && edges < maxEdges) {
                Function caller = iterator.next();
                callers++;
                // Use Ghidra's function-reference model; this may miss unresolved calls.
                List<Function> callees = new ArrayList<>(caller.getCalledFunctions(monitor));
                callees.sort(Comparator.comparing(f -> f.getEntryPoint().toString()));
                for (Function callee : callees) {
                    if (monitor.isCancelled() || edges >= maxEdges) {
                        break;
                    }
                    writer.beginObject();
                    writer.name("caller");
                    writeNode(writer, caller);
                    writer.name("callee");
                    writeNode(writer, callee);
                    writer.endObject();
                    edges++;
                }
            }
            writer.endArray();
        }
    }

    private void writeNode(JsonWriter writer, Function function) throws Exception {
        writer.beginObject();
        writer.name("name").value(function.getName());
        writer.name("entry").value(function.getEntryPoint().toString());
        writer.endObject();
    }
}
