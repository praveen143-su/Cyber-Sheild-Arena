package cybershield.defense;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Collection;
import java.util.Collections;

/**
 * DefenseAuditLogger — CyberShield Arena Phase 6
 *
 * OOP Concepts demonstrated:
 *   - File I/O & Resource Management : java.nio.file with try-with-resources.
 *   - RFC-4180 CSV Standard Compliance: Escapes quotes, commas, and newlines.
 *   - Audit Integrity               : Appends records continuously; logs successful, failed,
 *                                     and rejected actions; omits sensitive payload details.
 */
public class DefenseAuditLogger {

    public static final String DEFAULT_LOG_PATH = "logs/defense-audit.csv";
    private static final String CSV_HEADER =
            "actionId,timestamp,alertId,incidentId,actionType,targetId,success,resultDescription,failureReason\n";

    private final Path logFilePath;

    public DefenseAuditLogger() {
        this(DEFAULT_LOG_PATH);
    }

    public DefenseAuditLogger(String filePath) {
        if (filePath == null || filePath.trim().isEmpty()) {
            throw new IllegalArgumentException("Audit log file path cannot be blank.");
        }
        this.logFilePath = Paths.get(filePath.trim());
    }

    /**
     * Records a single defensive action to the CSV audit log.
     *
     * @param result     the executed DefenseResult
     * @param incidentId associated incident identifier (or "N/A")
     * @return true if successfully appended to the log file, false otherwise
     */
    public boolean logAction(DefenseResult result, String incidentId) {
        if (result == null) return false;
        return logActions(Collections.singletonList(result), incidentId) > 0;
    }

    /**
     * Appends a collection of defense results to the audit log.
     *
     * @param results    collection of DefenseResult objects
     * @param incidentId associated incident identifier
     * @return number of records successfully written
     */
    public synchronized int logActions(Collection<DefenseResult> results, String incidentId) {
        if (results == null || results.isEmpty()) return 0;

        try {
            // Ensure parent directory exists
            if (logFilePath.getParent() != null) {
                Files.createDirectories(logFilePath.getParent());
            }

            boolean fileExists = Files.exists(logFilePath) && Files.size(logFilePath) > 0;

            try (BufferedWriter writer = Files.newBufferedWriter(
                    logFilePath,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.APPEND)) {

                if (!fileExists) {
                    writer.write(CSV_HEADER);
                }

                int count = 0;
                String incId = (incidentId != null && !incidentId.trim().isEmpty()) ? incidentId.trim() : "N/A";

                for (DefenseResult res : results) {
                    writer.write(formatCsvRecord(res, incId));
                    writer.newLine();
                    count++;
                }

                writer.flush();
                return count;
            }
        } catch (IOException e) {
            System.err.printf("[DefenseAuditLogger] Failed to write audit record to %s: %s\n",
                    logFilePath, e.getMessage());
            return 0;
        }
    }

    private String formatCsvRecord(DefenseResult res, String incidentId) {
        return String.join(",",
                escapeCsv(res.getActionId()),
                escapeCsv(res.getTimestamp().toString()),
                escapeCsv(res.getAlertId()),
                escapeCsv(incidentId),
                escapeCsv(res.getActionType().name()),
                escapeCsv(res.getTargetId()),
                String.valueOf(res.isSuccess()),
                escapeCsv(res.getResultDescription()),
                escapeCsv(res.getFailureReason() != null ? res.getFailureReason() : "")
        );
    }

    /**
     * RFC-4180 compliant CSV escaping.
     */
    private String escapeCsv(String input) {
        if (input == null) return "";
        String field = input;
        boolean needsQuotes = field.contains(",") || field.contains("\"") || field.contains("\n") || field.contains("\r");
        if (field.contains("\"")) {
            field = field.replace("\"", "\"\"");
        }
        return needsQuotes ? "\"" + field + "\"" : field;
    }

    public Path getLogFilePath() {
        return logFilePath;
    }
}
