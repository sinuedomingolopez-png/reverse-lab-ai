// @category ReverseLab
// Export function names and entry addresses as JSON for a headless Ghidra run.
import com.google.gson.stream.JsonWriter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ExportFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args.length > 2) {
            throw new IllegalArgumentException("Expected output JSON filename and optional max function count");
        }
        int limit = args.length == 2 ? Integer.parseInt(args[1]) : 10000;
        if (limit < 1 || limit > 100000) {
            throw new IllegalArgumentException("Function limit must be 1..100000");
        }
        try (JsonWriter writer = new JsonWriter(
                Files.newBufferedWriter(Paths.get(args[0]), StandardCharsets.UTF_8))) {
            writer.beginArray();
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            int count = 0;
            while (functions.hasNext() && !monitor.isCancelled() && count < limit) {
                Function function = functions.next();
                writer.beginObject();
                writer.name("name").value(function.getName());
                writer.name("entry").value(function.getEntryPoint().toString());
                writer.endObject();
                count++;
            }
            writer.endArray();
        }
    }
}
