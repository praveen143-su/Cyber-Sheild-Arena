package cybershield.evaluation;

/**
 * EvaluationMetrics — CyberShield Arena Phase 7
 *
 * OOP Concepts demonstrated:
 *   - Encapsulation     : All metrics and counts are private and immutable (final).
 *   - Mathematical Rigor: Encapsulates standard machine learning and classification formulas.
 *   - Defensive Handling: Implements safe division-by-zero guards with explicit domain semantics.
 *
 * Class Semantics:
 *   - Positive Class : SUSPICIOUS (anomalous or malicious event)
 *   - Negative Class : NORMAL (benign operational traffic)
 */
public class EvaluationMetrics {

    private final String modelName;
    private final int truePositives;   // TP: Actual Attack correctly flagged as SUSPICIOUS
    private final int trueNegatives;   // TN: Actual Benign correctly identified as NORMAL
    private final int falsePositives;  // FP: Actual Benign mistakenly flagged as SUSPICIOUS (False Alarm)
    private final int falseNegatives;  // FN: Actual Attack missed and treated as NORMAL (Breach)

    private final double accuracy;
    private final double precision;
    private final double recall;
    private final double f1Score;
    private final double falsePositiveRate;

    /**
     * Constructs EvaluationMetrics and computes statistical metrics from raw counts.
     *
     * @param modelName      name of the detector or model
     * @param truePositives  TP count (>= 0)
     * @param trueNegatives  TN count (>= 0)
     * @param falsePositives FP count (>= 0)
     * @param falseNegatives FN count (>= 0)
     */
    public EvaluationMetrics(String modelName, int truePositives, int trueNegatives,
                             int falsePositives, int falseNegatives) {
        if (modelName == null || modelName.trim().isEmpty()) {
            throw new IllegalArgumentException("Model name must not be blank.");
        }
        if (truePositives < 0 || trueNegatives < 0 || falsePositives < 0 || falseNegatives < 0) {
            throw new IllegalArgumentException("Confusion matrix counts must be non-negative.");
        }

        this.modelName = modelName.trim();
        this.truePositives = truePositives;
        this.trueNegatives = trueNegatives;
        this.falsePositives = falsePositives;
        this.falseNegatives = falseNegatives;

        int total = truePositives + trueNegatives + falsePositives + falseNegatives;

        // Accuracy = (TP + TN) / Total
        this.accuracy = (total == 0) ? 0.0 : (double) (truePositives + trueNegatives) / total;

        // Precision = TP / (TP + FP)
        // Zero denominator semantic: If no positive predictions made, precision is 0.0
        int predictedPositives = truePositives + falsePositives;
        this.precision = (predictedPositives == 0) ? 0.0 : (double) truePositives / predictedPositives;

        // Recall (Sensitivity) = TP / (TP + FN)
        // Zero denominator semantic: If no actual positives exist in ground truth, recall is 1.0 (none missed)
        int actualPositives = truePositives + falseNegatives;
        this.recall = (actualPositives == 0) ? 1.0 : (double) truePositives / actualPositives;

        // F1-Score = 2 * (Precision * Recall) / (Precision + Recall)
        double prSum = this.precision + this.recall;
        this.f1Score = (prSum == 0.0) ? 0.0 : 2.0 * (this.precision * this.recall) / prSum;

        // False Positive Rate = FP / (FP + TN)
        // Zero denominator semantic: If no actual negatives exist, FPR is 0.0
        int actualNegatives = falsePositives + trueNegatives;
        this.falsePositiveRate = (actualNegatives == 0) ? 0.0 : (double) falsePositives / actualNegatives;
    }

    // ---------------------------------------------------------------
    // Getters
    // ---------------------------------------------------------------

    public String getModelName() { return modelName; }
    public int getTruePositives() { return truePositives; }
    public int getTrueNegatives() { return trueNegatives; }
    public int getFalsePositives() { return falsePositives; }
    public int getFalseNegatives() { return falseNegatives; }
    public int getTotalInstances() { return truePositives + trueNegatives + falsePositives + falseNegatives; }

    public double getAccuracy() { return accuracy; }
    public double getPrecision() { return precision; }
    public double getRecall() { return recall; }
    public double getF1Score() { return f1Score; }
    public double getFalsePositiveRate() { return falsePositiveRate; }

    /**
     * Renders an ASCII confusion matrix representation.
     */
    public String toConfusionMatrixString() {
        return String.format(
                "  Confusion Matrix [%s] (rows = Actual, cols = Predicted):\n" +
                "  +----------------------+--------------------+--------------------+\n" +
                "  | Actual \\ Predicted   | Pred SUSPICIOUS    | Pred NORMAL        |\n" +
                "  +----------------------+--------------------+--------------------+\n" +
                "  | Actual SUSPICIOUS    | TP = %-13d | FN = %-13d |\n" +
                "  | Actual NORMAL        | FP = %-13d | TN = %-13d |\n" +
                "  +----------------------+--------------------+--------------------+",
                modelName, truePositives, falseNegatives, falsePositives, trueNegatives
        );
    }

    @Override
    public String toString() {
        return String.format(
                "[%s Metrics] Acc: %.1f%% | Prec: %.4f | Rec: %.4f | F1: %.4f | FPR: %.4f (TP=%d, TN=%d, FP=%d, FN=%d)",
                modelName, accuracy * 100, precision, recall, f1Score, falsePositiveRate,
                truePositives, trueNegatives, falsePositives, falseNegatives
        );
    }
}
