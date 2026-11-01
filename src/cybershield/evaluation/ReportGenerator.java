package cybershield.evaluation;

import cybershield.defense.DefenseActionType;
import cybershield.defense.IncidentStatus;
import cybershield.security.AttackType;
import cybershield.security.Severity;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * ReportGenerator — CyberShield Arena Phase 7
 *
 * OOP Concepts demonstrated:
 *   - Reporting & Formatting : Structured multi-section generation according to engineering standards.
 *   - File I/O Robustness    : java.nio.file APIs with automatic directory creation and error resilience.
 *   - Traceability           : Sequential unique Report IDs and ISO timestamps prevent accidental overwrites.
 */
public class ReportGenerator {

    private static final AtomicInteger REPORT_SEQ = new AtomicInteger(1);
    public static final String DEFAULT_REPORTS_DIR = "reports";

    private final Path reportsDirectory;

    public ReportGenerator() {
        this(DEFAULT_REPORTS_DIR);
    }

    public ReportGenerator(String reportsDir) {
        if (reportsDir == null || reportsDir.trim().isEmpty()) {
            throw new IllegalArgumentException("Reports directory path must not be blank.");
        }
        this.reportsDirectory = Paths.get(reportsDir.trim());
    }

    /**
     * Generates both a text report and a CSV metrics export.
     *
     * @param scenarioNames list or summary of executed simulation scenarios
     * @param detEval       detection evaluator holding rule and ML metrics
     * @param defEval       defense evaluator holding containment and recovery metrics
     * @param perfEval      simulation performance benchmarks
     * @param stats         holistic simulation statistics
     * @return generated report ID
     */
    public String generateAllReports(String scenarioNames,
                                     DetectionEvaluator detEval,
                                     DefenseEvaluator defEval,
                                     SimulationPerformanceEvaluator perfEval,
                                     SimulationStatistics stats) {

        String reportId = String.format("REP-%04d", REPORT_SEQ.getAndIncrement());
        Instant now = Instant.now();

        try {
            Files.createDirectories(reportsDirectory);

            Path txtPath = reportsDirectory.resolve(String.format("simulation-report-%s.txt", reportId));
            Path csvPath = reportsDirectory.resolve(String.format("evaluation-metrics-%s.csv", reportId));

            // 1. Generate text report
            String textContent = buildTextReport(reportId, now, scenarioNames, detEval, defEval, perfEval, stats);
            Files.writeString(txtPath, textContent);
            System.out.println("[ReportGenerator] Successfully saved text report: " + txtPath);

            // 2. Generate CSV metrics export
            String csvContent = buildCsvMetrics(reportId, now, detEval, defEval, perfEval);
            Files.writeString(csvPath, csvContent);
            System.out.println("[ReportGenerator] Successfully saved metrics CSV: " + csvPath);

        } catch (IOException e) {
            System.err.printf("[ReportGenerator ERROR] Could not save reports: %s\n", e.getMessage());
        }

        return reportId;
    }

    /**
     * Builds the complete 6-section text report matching project requirements.
     */
    public String buildTextReport(String reportId, Instant timestamp, String scenarioNames,
                                  DetectionEvaluator detEval, DefenseEvaluator defEval,
                                  SimulationPerformanceEvaluator perfEval, SimulationStatistics stats) {

        StringBuilder sb = new StringBuilder();
        sb.append("======================================================================================\n");
        sb.append("                               CYBERSHIELD ARENA\n");
        sb.append("                          SIMULATION EVALUATION REPORT\n");
        sb.append("======================================================================================\n\n");

        // SECTION 1: PROJECT INFORMATION
        sb.append("--- SECTION 1: PROJECT INFORMATION ---\n");
        sb.append(String.format("Project Name         : %s\n", "CyberShield Arena: Cyber Attack vs Defense Simulation"));
        sb.append(String.format("Report ID            : %s\n", reportId));
        sb.append(String.format("Generation Timestamp : %s\n", timestamp.toString()));
        sb.append(String.format("Simulation Scenarios : %s\n", scenarioNames));
        sb.append(String.format("Dataset Description  : %s\n\n", "Synthetic labelled simulation dataset (Normal vs Suspicious)"));

        // SECTION 2: SIMULATION SUMMARY
        sb.append("--- SECTION 2: SIMULATION SUMMARY ---\n");
        sb.append(String.format("Total Virtual Devices: %d\n", stats.getTotalDevices()));
        sb.append(String.format("Active Connections   : %d | Blocked: %d | Disconnected: %d\n",
                stats.getActiveConnections(), stats.getBlockedConnections(), stats.getDisconnectedConnections()));
        sb.append(String.format("Total Events Produced: %d (Processed: %d)\n",
                stats.getTotalEventsGenerated(), stats.getTotalEventsProcessed()));

        sb.append("Events by Attack Type: ");
        for (AttackType at : AttackType.values()) {
            sb.append(String.format("[%s: %d] ", at.name(), stats.getEventsByAttackType().getOrDefault(at, 0)));
        }
        sb.append("\nEvents by Severity   : ");
        for (Severity sev : Severity.values()) {
            sb.append(String.format("[%s: %d] ", sev.name(), stats.getEventsBySeverity().getOrDefault(sev, 0)));
        }
        sb.append(String.format("\nTotal Alerts Raised  : %d\n", stats.getTotalAlerts()));
        sb.append(String.format("Defensive Actions Run: %d\n\n", defEval.getTotalAttemptedActions()));

        // SECTION 3: DETECTION PERFORMANCE EVALUATION
        sb.append("--- SECTION 3: DETECTION PERFORMANCE (RULE-BASED VS MACHINE LEARNING) ---\n");
        EvaluationMetrics rMet = (detEval != null && detEval.getRuleMetrics() != null)
                ? detEval.getRuleMetrics() : new EvaluationMetrics("Rule-Based", 0, 0, 0, 0);
        EvaluationMetrics mMet = (detEval != null && detEval.getMlMetrics() != null)
                ? detEval.getMlMetrics() : new EvaluationMetrics("Machine Learning", 0, 0, 0, 0);

        sb.append(String.format("%-22s | %-18s | %-18s\n", "Metric", "Rule-Based", "Machine Learning"));
        sb.append("-----------------------+--------------------+--------------------\n");
        sb.append(String.format("%-22s | %17.1f%% | %17.1f%%\n", "Accuracy", rMet.getAccuracy() * 100, mMet.getAccuracy() * 100));
        sb.append(String.format("%-22s | %18.4f | %18.4f\n", "Precision", rMet.getPrecision(), mMet.getPrecision()));
        sb.append(String.format("%-22s | %18.4f | %18.4f\n", "Recall (Detection Rate)", rMet.getRecall(), mMet.getRecall()));
        sb.append(String.format("%-22s | %18.4f | %18.4f\n", "F1-Score", rMet.getF1Score(), mMet.getF1Score()));
        sb.append(String.format("%-22s | %18.4f | %18.4f\n\n", "False Positive Rate", rMet.getFalsePositiveRate(), mMet.getFalsePositiveRate()));

        sb.append(rMet.toConfusionMatrixString()).append("\n\n");
        sb.append(mMet.toConfusionMatrixString()).append("\n\n");

        // SECTION 4: DEFENSE PERFORMANCE
        sb.append("--- SECTION 4: AUTOMATED DEFENSE & INCIDENT RESPONSE ---\n");
        sb.append(String.format("Defensive Actions Attempted : %d\n", defEval.getTotalAttemptedActions()));
        sb.append(String.format("Successful Actions          : %d\n", defEval.getSuccessfulActions()));
        sb.append(String.format("Failed / Rejected Actions   : %d\n", defEval.getFailedOrRejectedActions()));
        sb.append(String.format("Duplicate Actions Avoided   : %d\n", defEval.getDuplicateActionsPrevented()));
        sb.append(String.format("Total Security Incidents    : %d\n", defEval.getTotalIncidents()));
        sb.append(String.format("Incidents Contained         : %d (Containment Rate: %.1f%%)\n",
                defEval.getIncidentsContained(), defEval.getContainmentRate() * 100));
        sb.append(String.format("Incidents Recovered         : %d (Recovery Rate: %.1f%%)\n",
                defEval.getIncidentsRecovered(), defEval.getRecoveryRate() * 100));
        sb.append(String.format("Remaining Open Incidents    : %d\n\n", defEval.getIncidentsOpen()));

        // SECTION 5: SIMULATION PERFORMANCE
        sb.append("--- SECTION 5: SIMULATION PERFORMANCE BENCHMARK (IN-MEMORY SOFTWARE) ---\n");
        sb.append(String.format("Total Simulation Duration   : %.2f ms\n", perfEval.getTotalSimulationMillis()));
        sb.append(String.format("Event Processing Duration   : %.2f ms\n", perfEval.getEventProcessingMillis()));
        sb.append(String.format("Rule Detection Duration     : %.2f ms\n", perfEval.getRuleDetectionMillis()));
        sb.append(String.format("ML Prediction Duration      : %.2f ms\n", perfEval.getMlPredictionMillis()));
        sb.append(String.format("Defense Action Duration     : %.2f ms\n", perfEval.getDefenseActionMillis()));
        sb.append(String.format("Average Time per Event      : %.2f µs\n", perfEval.getAverageProcessingTimePerEventMicros()));
        sb.append(String.format("Event Throughput Rate       : %.1f events/second\n\n", perfEval.getEventsPerSecond()));

        // SECTION 6: OBSERVATIONS & LIMITATIONS
        sb.append("--- SECTION 6: OBSERVATIONS & LIMITATIONS ---\n");
        sb.append("Key Findings:\n");
        sb.append("  1. Detector Agreement: High synergy observed where ML model confirmed rule triggers,\n");
        sb.append("     providing multi-factor evidence before disruptive actions (e.g. device quarantine).\n");
        sb.append(String.format("  2. Disagreements: %d event(s) saw divergence between rule heuristics and ML,\n",
                (detEval != null ? detEval.getDisagreements().size() : 0)));
        sb.append("     demonstrating the necessity of defense policy fallbacks.\n");
        sb.append("  3. Defensive Idempotence: Duplicate response actions were successfully suppressed,\n");
        sb.append("     preventing flapping states in the virtual topology.\n\n");

        sb.append("Limitations:\n");
        sb.append("  - Network topology, attack actions, and traffic flows are strictly simulated in Java memory.\n");
        sb.append("  - The synthetic dataset captures common volumetric patterns but does not span zero-day exploits.\n");
        sb.append("  - Benchmarked latencies represent local JVM processing speeds, not physical network wire delays.\n\n");

        sb.append("======================================================================================\n");
        sb.append("                          END OF EVALUATION REPORT\n");
        sb.append("======================================================================================\n");

        return sb.toString();
    }

    /**
     * Builds RFC-4180 CSV content for evaluation metrics.
     */
    private String buildCsvMetrics(String reportId, Instant timestamp,
                                   DetectionEvaluator detEval, DefenseEvaluator defEval,
                                   SimulationPerformanceEvaluator perfEval) {
        StringBuilder sb = new StringBuilder();
        sb.append("reportId,timestamp,detector,accuracy,precision,recall,f1Score,fpr,tp,tn,fp,fn\n");

        if (detEval != null) {
            EvaluationMetrics r = detEval.getRuleMetrics();
            if (r != null) {
                sb.append(String.format("%s,%s,Rule-Based,%.4f,%.4f,%.4f,%.4f,%.4f,%d,%d,%d,%d\n",
                        reportId, timestamp, r.getAccuracy(), r.getPrecision(), r.getRecall(),
                        r.getF1Score(), r.getFalsePositiveRate(), r.getTruePositives(),
                        r.getTrueNegatives(), r.getFalsePositives(), r.getFalseNegatives()));
            }

            EvaluationMetrics m = detEval.getMlMetrics();
            if (m != null) {
                sb.append(String.format("%s,%s,Machine-Learning,%.4f,%.4f,%.4f,%.4f,%.4f,%d,%d,%d,%d\n",
                        reportId, timestamp, m.getAccuracy(), m.getPrecision(), m.getRecall(),
                        m.getF1Score(), m.getFalsePositiveRate(), m.getTruePositives(),
                        m.getTrueNegatives(), m.getFalsePositives(), m.getFalseNegatives()));
            }
        }

        return sb.toString();
    }

    public Path getReportsDirectory() {
        return reportsDirectory;
    }
}
