package cybershield.evaluation;

/**
 * SimulationPerformanceEvaluator — CyberShield Arena Phase 7
 *
 * OOP Concepts demonstrated:
 *   - Precision Benchmarking: Uses System.nanoTime() exclusively for elapsed time measurement.
 *   - Boundary Separation   : Accurately separates model inference, rule parsing, and response dispatch.
 *   - Scope Disclaimer      : Explicitly labels measurements as simulated in-memory application performance.
 */
public class SimulationPerformanceEvaluator {

    private long simulationStartNano;
    private long simulationEndNano;

    private long eventProcessingNanos;
    private long ruleDetectionNanos;
    private long mlPredictionNanos;
    private long defenseActionNanos;

    private int totalEventsProcessed;

    public SimulationPerformanceEvaluator() {
        // Default constructor
    }

    public void startSimulation() {
        this.simulationStartNano = System.nanoTime();
    }

    public void stopSimulation() {
        this.simulationEndNano = System.nanoTime();
    }

    public void recordEventProcessingTime(long elapsedNanos) {
        if (elapsedNanos > 0) this.eventProcessingNanos += elapsedNanos;
    }

    public void recordRuleDetectionTime(long elapsedNanos) {
        if (elapsedNanos > 0) this.ruleDetectionNanos += elapsedNanos;
    }

    public void recordMlPredictionTime(long elapsedNanos) {
        if (elapsedNanos > 0) this.mlPredictionNanos += elapsedNanos;
    }

    public void recordDefenseActionTime(long elapsedNanos) {
        if (elapsedNanos > 0) this.defenseActionNanos += elapsedNanos;
    }

    public void setTotalEventsProcessed(int totalEvents) {
        this.totalEventsProcessed = Math.max(0, totalEvents);
    }

    // ---------------------------------------------------------------
    // Computed Time Metrics
    // ---------------------------------------------------------------

    public long getTotalSimulationNanos() {
        return (simulationEndNano > simulationStartNano) ? (simulationEndNano - simulationStartNano) : 0;
    }

    public double getTotalSimulationMillis() {
        return getTotalSimulationNanos() / 1_000_000.0;
    }

    public double getEventProcessingMillis() {
        return eventProcessingNanos / 1_000_000.0;
    }

    public double getRuleDetectionMillis() {
        return ruleDetectionNanos / 1_000_000.0;
    }

    public double getMlPredictionMillis() {
        return mlPredictionNanos / 1_000_000.0;
    }

    public double getDefenseActionMillis() {
        return defenseActionNanos / 1_000_000.0;
    }

    public double getAverageProcessingTimePerEventMicros() {
        if (totalEventsProcessed == 0) return 0.0;
        return (eventProcessingNanos / 1_000.0) / totalEventsProcessed;
    }

    public double getEventsPerSecond() {
        double sec = eventProcessingNanos / 1_000_000_000.0;
        if (sec <= 0.0 || totalEventsProcessed == 0) return 0.0;
        return totalEventsProcessed / sec;
    }

    public int getTotalEventsProcessed() {
        return totalEventsProcessed;
    }

    @Override
    public String toString() {
        return String.format(
                "Performance Benchmark (In-Memory Simulation):\n" +
                "  Total Duration       : %.2f ms\n" +
                "  Event Processing     : %.2f ms\n" +
                "  Rule Detection Time  : %.2f ms\n" +
                "  ML Prediction Time   : %.2f ms\n" +
                "  Defense Action Time  : %.2f ms\n" +
                "  Avg Time per Event   : %.2f µs\n" +
                "  Throughput           : %.1f events/sec",
                getTotalSimulationMillis(), getEventProcessingMillis(),
                getRuleDetectionMillis(), getMlPredictionMillis(), getDefenseActionMillis(),
                getAverageProcessingTimePerEventMicros(), getEventsPerSecond()
        );
    }
}
