package cybershield.ml;

import weka.classifiers.Evaluation;
import weka.core.Instances;

/**
 * ModelEvaluator — CyberShield Arena Phase 5
 *
 * OOP Concepts demonstrated:
 *   - Separation of Concerns : Evaluation logic lives here, not in DecisionTreeDetector.
 *   - Encapsulation          : Raw Weka Evaluation state is wrapped; callers get clean numbers.
 *   - Defensive Programming  : Handles NaN (undefined metric) and division-by-zero gracefully.
 *
 * ─── Why these metrics? ──────────────────────────────────────────────────────
 * Accuracy alone can be misleading for security data.  Imagine 95 % normal events:
 * a model that always predicts NORMAL gets 95 % accuracy but catches ZERO attacks.
 *
 *   Accuracy          = (TP + TN) / total          — overall correctness
 *   Precision         = TP / (TP + FP)             — "of flagged attacks, how many are real?"
 *   Recall            = TP / (TP + FN)             — "of real attacks, how many did we catch?"
 *   F1-Score          = 2 × Precision × Recall
 *                           / (Precision + Recall)  — balance between precision and recall
 *   False Positive Rate = FP / (FP + TN)           — how often do normal events get wrongly flagged?
 *
 * TP = True Positive   (SUSPICIOUS correctly predicted as SUSPICIOUS)
 * TN = True Negative   (NORMAL correctly predicted as NORMAL)
 * FP = False Positive  (NORMAL wrongly predicted as SUSPICIOUS — false alarm)
 * FN = False Negative  (SUSPICIOUS wrongly predicted as NORMAL — missed attack)
 *
 * IMPORTANT:
 *   evaluate() uses ONLY the held-out test split.
 *   The training data is passed only to set class priors inside Weka's Evaluation object —
 *   the classifier is NOT retrained on test data.
 *
 * The positive class is SUSPICIOUS (index 1).
 */
public class ModelEvaluator {

    private Evaluation wekaEvaluation;
    private int suspiciousClassIdx = -1;
    private int normalClassIdx     = -1;
    private boolean evaluated = false;

    // ---------------------------------------------------------------
    // Evaluation
    // ---------------------------------------------------------------

    /**
     * Evaluates the trained DecisionTreeDetector on held-out test examples.
     *
     * @param detector  the trained detector (must have isTrained() == true)
     * @param trainData the training instances — used by Weka to compute class priors only
     * @param testData  the held-out test instances — MUST NOT overlap with training data
     * @throws Exception if Weka's evaluation routine fails
     */
    public void evaluate(DecisionTreeDetector detector,
                         Instances trainData, Instances testData) throws Exception {
        if (!detector.isTrained()) {
            throw new IllegalStateException("Cannot evaluate: model has not been trained.");
        }
        if (testData == null || testData.isEmpty()) {
            throw new IllegalArgumentException("Test data must not be null or empty.");
        }

        // Look up class indices so we can report metrics for the right class
        suspiciousClassIdx = testData.classAttribute().indexOfValue(
                PredictionClass.SUSPICIOUS.name());
        normalClassIdx     = testData.classAttribute().indexOfValue(
                PredictionClass.NORMAL.name());

        if (suspiciousClassIdx < 0) {
            throw new IllegalArgumentException(
                "Test data does not contain the SUSPICIOUS class label. Check your CSV.");
        }

        // trainData is used only for computing class priors — no retraining occurs
        wekaEvaluation = new Evaluation(trainData);
        wekaEvaluation.evaluateModel(detector.getClassifier(), testData);
        evaluated = true;

        System.out.printf("[EVALUATOR] Evaluation completed on %d test examples.%n", testData.size());
    }

    // ---------------------------------------------------------------
    // Display
    // ---------------------------------------------------------------

    /**
     * Prints all metrics to the console in a readable table.
     */
    public void displayMetrics() {
        if (!evaluated) {
            System.out.println("[EVALUATOR] No results available. Call evaluate() first.");
            return;
        }

        System.out.println("\n========================================");
        System.out.println("        MODEL EVALUATION RESULTS        ");
        System.out.println("========================================");
        System.out.println("  (Positive class = SUSPICIOUS)");
        System.out.println();

        double accuracy  = wekaEvaluation.pctCorrect() / 100.0;
        double precision = safeValue(wekaEvaluation.precision(suspiciousClassIdx));
        double recall    = safeValue(wekaEvaluation.recall(suspiciousClassIdx));
        double f1        = safeValue(wekaEvaluation.fMeasure(suspiciousClassIdx));
        double fpr       = safeValue(wekaEvaluation.falsePositiveRate(suspiciousClassIdx));

        System.out.printf("  Accuracy             : %.4f  (%.1f%%)%n", accuracy, accuracy * 100);
        System.out.printf("  Precision            : %.4f%n", precision);
        System.out.printf("  Recall               : %.4f%n", recall);
        System.out.printf("  F1-Score             : %.4f%n", f1);
        System.out.printf("  False Positive Rate  : %.4f%n", fpr);

        // ── Confusion Matrix ──────────────────────────────────────
        System.out.println();
        System.out.println("  Confusion Matrix  (rows = Actual, cols = Predicted):");
        System.out.println("  ┌──────────────────────┬──────────────┬────────────────┐");
        System.out.println("  │                      │ Pred: NORMAL │ Pred: SUSPIC.  │");
        System.out.println("  ├──────────────────────┼──────────────┼────────────────┤");
        try {
            double[][] cm = wekaEvaluation.confusionMatrix();
            // Weka layout: cm[actual][predicted]
            int tn = (int) cm[normalClassIdx][normalClassIdx];
            int fp = (int) cm[normalClassIdx][suspiciousClassIdx];
            int fn = (int) cm[suspiciousClassIdx][normalClassIdx];
            int tp = (int) cm[suspiciousClassIdx][suspiciousClassIdx];

            System.out.printf("  │ Actual: NORMAL       │ TN = %6d   │ FP = %9d  │%n", tn, fp);
            System.out.printf("  │ Actual: SUSPICIOUS   │ FN = %6d   │ TP = %9d  │%n", fn, tp);
            System.out.println("  └──────────────────────┴──────────────┴────────────────┘");
            System.out.println();
            System.out.printf("  TP %-3d — correctly identified attacks (good)%n", tp);
            System.out.printf("  TN %-3d — correctly identified normal events (good)%n", tn);
            System.out.printf("  FP %-3d — normal events wrongly flagged as suspicious (false alarms)%n", fp);
            System.out.printf("  FN %-3d — attacks the model missed (misses)%n", fn);
        } catch (Exception e) {
            System.err.println("  Could not render confusion matrix: " + e.getMessage());
        }

        System.out.println("========================================");
    }

    // ---------------------------------------------------------------
    // Getters  (return -1.0 if not yet evaluated)
    // ---------------------------------------------------------------

    public double getAccuracy()          { return evaluated ? wekaEvaluation.pctCorrect() / 100.0                         : -1.0; }
    public double getPrecision()         { return evaluated ? safeValue(wekaEvaluation.precision(suspiciousClassIdx))      : -1.0; }
    public double getRecall()            { return evaluated ? safeValue(wekaEvaluation.recall(suspiciousClassIdx))         : -1.0; }
    public double getF1Score()           { return evaluated ? safeValue(wekaEvaluation.fMeasure(suspiciousClassIdx))       : -1.0; }
    public double getFalsePositiveRate() { return evaluated ? safeValue(wekaEvaluation.falsePositiveRate(suspiciousClassIdx)) : -1.0; }
    public boolean isEvaluated()         { return evaluated; }

    /**
     * Weka uses Double.NaN for undefined metrics (e.g. precision when zero positive predictions exist).
     * We replace NaN with 0.0 so callers never receive a NaN.
     */
    private double safeValue(double v) { return Double.isNaN(v) ? 0.0 : v; }
}
