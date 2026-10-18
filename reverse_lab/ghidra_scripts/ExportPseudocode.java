// @category ReverseLab
// Export bounded approximate C pseudocode for authorized samples.
// Generated pseudocode is untrusted data, NOT the original source code.
import com.google.gson.stream.JsonWriter;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ExportPseudocode extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4) {
            throw new IllegalArgumentException("Expected output path, max functions, max chars and seconds per function");
        }
        int maxFunctions = Integer.parseInt(args[1]);
        int maxChars = Integer.parseInt(args[2]);
        int seconds = Integer.parseInt(args[3]);
        if (maxFunctions < 1 || maxFunctions > 50 ||
            maxChars < 256 || maxChars > 16000 || seconds < 1 || seconds > 30) {
            throw new IllegalArgumentException("Export limits out of range");
        }
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Unable to initialize the decompiler");
        }
        try {
            try (JsonWriter writer = new JsonWriter(
                    Files.newBufferedWriter(Paths.get(args[0]), StandardCharsets.UTF_8))) {
                writer.beginArray();
                FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
                int count = 0;
                while (iterator.hasNext() && !monitor.isCancelled() && count < maxFunctions) {
                    Function function = iterator.next();
                    writer.beginObject();
                    writer.name("name").value(function.getName());
                    writer.name("entry").value(function.getEntryPoint().toString());
                    try {
                        DecompileResults result = decompiler.decompileFunction(function, seconds, monitor);
                        DecompiledFunction decompiled = result != null && result.decompileCompleted()
                                ? result.getDecompiledFunction() : null;
                        if (decompiled != null && decompiled.getC() != null) {
                            String cText = decompiled.getC();
                            boolean truncated = cText.length() > maxChars;
                            writer.name("pseudocode").value(truncated ? cText.substring(0, maxChars) : cText);
                            writer.name("truncated").value(truncated);
                        } else {
                            String message = result == null ? "No decompiler result" : result.getErrorMessage();
                            writer.name("error").value(message == null ? "Unavailable" :
                                    message.substring(0, Math.min(message.length(), 250)));
                        }
                    } catch (Exception exc) {
                        String message = exc.getMessage();
                        writer.name("error").value(message == null ? "Decompiler error" :
                                message.substring(0, Math.min(message.length(), 250)));
                    }
                    writer.endObject();
                    count++;
                }
                writer.endArray();
            }
        } finally {
            decompiler.dispose();
        }
    }
}
