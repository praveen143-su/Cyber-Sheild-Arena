package cybershield.evaluation;

import cybershield.defense.DefenseResult;
import cybershield.defense.SecurityIncident;
import cybershield.ml.MLDetectionEngine;
import cybershield.ml.ThreatPrediction;
import cybershield.monitoring.RuleBasedDetectionEngine;
import cybershield.monitoring.SecurityAlert;
import cybershield.network.NetworkTopology;
import cybershield.network.VirtualNetwork;
import cybershield.security.SecurityEvent;
import weka.core.Instances;

import java.util.Collection;
import java.util.List;

/**
 * EvaluationCoordinator — CyberShield Arena Phase 7
 *
 * OOP Concepts demonstrated:
 *   - Orchestrator / Facade Pattern : Centrally coordinates all Phase 7 evaluation subsystems.
 *   - Clean Separation of Concerns  : Keeps Main.java clean and modular; handles metrics gathering,
 *                                     statistical aggregation, and reporting in a dedicated component.
 */
public class EvaluationCoordinator {

    private final DetectionEvaluator detectionEvaluator;
    private DefenseEvaluator defenseEvaluator;
    private final SimulationPerformanceEvaluator performanceEvaluator;
    private SimulationStatistics statistics;
    private final ReportGenerator reportGenerator;

    private String lastGeneratedReportId;

    public EvaluationCoordinator() {
        this(new ReportGenerator());
    }

    public EvaluationCoordinator(ReportGenerator reportGenerator) {
        this.detectionEvaluator = new DetectionEvaluator();
        this.performanceEvaluator = new SimulationPerformanceEvaluator();
        this.reportGenerator = reportGenerator;
    }

    /**
     * Executes the comprehensive evaluation across detection, defense, performance, and statistics.
     */
    public String runEvaluation(String scenarioTitle,
                                Instances testInstances,
                                MLDetectionEngine mlEngine,
                                RuleBasedDetectionEngine ruleEngine,
                                Collection<SecurityEvent> events,
                                Collection<SecurityAlert> alerts,
                                Collection<ThreatPrediction> predictions,
                                Collection<DefenseResult> defenseActions,
                                Collection<SecurityIncident> incidents,
                                VirtualNetwork vnet,
                                NetworkTopology topology) {

        // 1. Evaluate detection performance on unseen test split
        detectionEvaluator.evaluateOnTestInstances(testInstances, mlEngine, ruleEngine);

        // 2. Evaluate defense response and incident containment
        this.defenseEvaluator = new DefenseEvaluator(defenseActions, incidents);

        // 3. Aggregate holistic simulation statistics
        this.statistics = new SimulationStatistics(events, alerts, predictions, defenseActions, incidents, vnet, topology);

        // 4. Update performance evaluator with event counts
        if (events != null) {
            performanceEvaluator.setTotalEventsProcessed(events.size());
        }

        // 5. Generate and persist structured reports (Text and CSV)
        this.lastGeneratedReportId = reportGenerator.generateAllReports(
                scenarioTitle, detectionEvaluator, defenseEvaluator, performanceEvaluator, statistics
        );

        return lastGeneratedReportId;
    }

    public void displayEvaluationDashboard() {
        System.out.println("\n+----------------------------------------------------------------------------------------------------+");
        System.out.printf("| %-98s |\n", "PHASE 7 EVALUATION & BENCHMARKING DASHBOARD");
        System.out.println("+----------------------------------------------------------------------------------------------------+");

        EvaluationMetrics r = detectionEvaluator.getRuleMetrics();
        EvaluationMetrics m = detectionEvaluator.getMlMetrics();

        System.out.println("\n  [DETECTION ACCURACY & CLASSIFICATION METRICS]");
        System.out.printf("  %-24s | %-16s | %-16s\n", "Metric", "Rule-Based", "Decision Tree ML");
        System.out.println("  -------------------------+------------------+------------------");
        System.out.printf("  %-24s | %15.1f%% | %15.1f%%\n", "Accuracy", r.getAccuracy() * 100, m.getAccuracy() * 100);
        System.out.printf("  %-24s | %16.4f | %16.4f\n", "Precision", r.getPrecision(), m.getPrecision());
        System.out.printf("  %-24s | %16.4f | %16.4f\n", "Recall (Detection Rate)", r.getRecall(), m.getRecall());
        System.out.printf("  %-24s | %16.4f | %16.4f\n", "F1-Score", r.getF1Score(), m.getF1Score());
        System.out.printf("  %-24s | %16.4f | %16.4f\n", "False Positive Rate", r.getFalsePositiveRate(), m.getFalsePositiveRate());

        if (defenseEvaluator != null) {
            System.out.println("\n  [AUTOMATED DEFENSE & CONTAINMENT EFFECTIVENESS]");
            System.out.printf("  Total Actions Run : %-5d | Successful: %-5d | Failed/Rejected: %-5d\n",
                    defenseEvaluator.getTotalAttemptedActions(), defenseEvaluator.getSuccessfulActions(),
                    defenseEvaluator.getFailedOrRejectedActions());
            System.out.printf("  Incident Status   : Total=%d | Contained=%d (%.1f%%) | Recovered=%d (%.1f%%) | Open=%d\n",
                    defenseEvaluator.getTotalIncidents(),
                    defenseEvaluator.getIncidentsContained(), defenseEvaluator.getContainmentRate() * 100,
                    defenseEvaluator.getIncidentsRecovered(), defenseEvaluator.getRecoveryRate() * 100,
                    defenseEvaluator.getIncidentsOpen());
        }

        System.out.println("\n  [SIMULATION PERFORMANCE & THROUGHPUT]");
        System.out.printf("  Total Sim Duration: %.2f ms | Event Processing: %.2f ms | ML Prediction: %.2f ms\n",
                performanceEvaluator.getTotalSimulationMillis(), performanceEvaluator.getEventProcessingMillis(),
                performanceEvaluator.getMlPredictionMillis());
        System.out.printf("  Avg Time per Event: %.2f µs | Throughput: %.1f events/second\n",
                performanceEvaluator.getAverageProcessingTimePerEventMicros(), performanceEvaluator.getEventsPerSecond());

        System.out.println("+----------------------------------------------------------------------------------------------------+\n");
    }

    public DetectionEvaluator getDetectionEvaluator() { return detectionEvaluator; }
    public DefenseEvaluator getDefenseEvaluator() { return defenseEvaluator; }
    public SimulationPerformanceEvaluator getPerformanceEvaluator() { return performanceEvaluator; }
    public SimulationStatistics getStatistics() { return statistics; }
    public ReportGenerator getReportGenerator() { return reportGenerator; }
    public String getLastGeneratedReportId() { return lastGeneratedReportId; }
}
