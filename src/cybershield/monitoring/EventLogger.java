package cybershield.monitoring;

import cybershield.security.SecurityEvent;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Collection;

/**
 * EventLogger — CyberShield Arena Phase 4
 *
 * OOP Concepts demonstrated:
 *   - File I/O & Resource Management : Try-with-resources with java.nio.file APIs.
 *   - Defensive Error Handling       : Handles missing directories and file write faults gracefully.
 *   - RFC-4180 CSV Conformance      : Robust escaping for quotes, commas, and newlines.
 *   - Security Hygiene               : Strips sensitive credential payloads from persistence.
 *
 * Persists security events into an audit log CSV file (e.g. logs/security-events.csv).
 */
public class EventLogger {

    public static final String DEFAULT_LOG_PATH = "logs/security-events.csv";
    private static final String CSV_HEADER =
            "eventId,timestamp,attackType,sourceNodeId,targetNodeId,severity,failedLoginCount,connectionAttemptCount,uniquePortCount,firewallAction,eventDescription\n";

    private final Path logFilePath;

    public EventLogger() {
        this(DEFAULT_LOG_PATH);
    }

    public EventLogger(String filePath) {
        if (filePath == null || filePath.trim().isEmpty()) {
            throw new IllegalArgumentException("Log file path cannot be blank.");
        }
        this.logFilePath = Paths.get(filePath.trim());
    }

    /**
     * Appends a single SecurityEvent to the CSV file.
     *
     * @param event the event to log
     * @return true if successfully written, false otherwise
     */
    public boolean logEvent(SecurityEvent event) {
        if (event == null) return false;
        return logEvents(java.util.Collections.singletonList(event)) > 0;
    }

    /**
     * Appends a batch of SecurityEvents to the CSV file.
     * Automatically writes header if the file is new or empty.
     *
     * @param events collection of SecurityEvents to append
     * @return count of successfully written events
     */
    public int logEvents(Collection<SecurityEvent> events) {
        if (events == null || events.isEmpty()) {
            return 0;
        }

        try {
            // Ensure parent directories exist
            if (logFilePath.getParent() != null && !Files.exists(logFilePath.getParent())) {
                Files.createDirectories(logFilePath.getParent());
            }

            boolean isNewOrEmpty = !Files.exists(logFilePath) || Files.size(logFilePath) == 0;

            try (BufferedWriter writer = Files.newBufferedWriter(logFilePath,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {

                if (isNewOrEmpty) {
                    writer.write(CSV_HEADER);
                }

                int count = 0;
                for (SecurityEvent ev : events) {
                    writer.write(formatCsvRecord(ev));
                    count++;
                }
                writer.flush();
                return count;
            }
        } catch (IOException e) {
            System.err.printf("[EventLogger] Failed to write events to %s: %s\n",
                    logFilePath, e.getMessage());
            return 0;
        }
    }

    /**
     * Formats a SecurityEvent into an RFC-4180 compliant CSV line.
     */
    public String formatCsvRecord(SecurityEvent event) {
        String fwStr = event.getFirewallAction().map(Enum::name).orElse("N/A");

        return String.join(",",
                escapeCsv(event.getEventId()),
                escapeCsv(event.getTimestamp().toString()),
                escapeCsv(event.getAttackType().name()),
                escapeCsv(event.getSourceNodeId()),
                escapeCsv(event.getTargetNodeId()),
                escapeCsv(event.getSeverity().name()),
                String.valueOf(event.getFailedLoginCount()),
                String.valueOf(event.getConnectionAttemptCount()),
                String.valueOf(event.getUniquePortCount()),
                escapeCsv(fwStr),
                escapeCsv(event.getEventDescription())
        ) + "\n";
    }

    /**
     * Escapes a field according to RFC-4180:
     * If the string contains comma, double-quote, or newline, wrap in quotes and double internal quotes.
     */
    public static String escapeCsv(String field) {
        if (field == null) {
            return "";
        }
        if (field.contains(",") || field.contains("\"") || field.contains("\n") || field.contains("\r")) {
            return "\"" + field.replace("\"", "\"\"") + "\"";
        }
        return field;
    }

    public Path getLogFilePath() {
        return logFilePath;
    }
}
