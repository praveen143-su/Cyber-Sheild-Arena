package cybershield.evaluation;

import cybershield.ml.MLDetectionEngine;
import cybershield.ml.PredictionClass;
import cybershield.ml.ThreatPrediction;
import cybershield.monitoring.DetectionResult;
import cybershield.monitoring.RuleBasedDetectionEngine;
import cybershield.security.AttackType;
import cybershield.security.SecurityEvent;
import weka.core.Instance;
import weka.core.Instances;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * DetectionEvaluator — CyberShield Arena Phase 7
 *
 * OOP Concepts demonstrated:
 *   - Comparative Evaluation: Evaluates rule-based and machine-learning detectors on identical test cases.
 *   - Ground Truth Integrity: Never uses one detector's output as ground truth for the other.
 *   - Disagreement Analysis : Tracks forensic discrepancies where detectors disagree or fail.
 */
public class DetectionEvaluator {

    /**
     * Inner record representing a single evaluated test case.
     */
    public static class EvaluationRecord {
        private final String caseId;
        private final String description;
        private final PredictionClass groundTruth;
        private final PredictionClass rulePrediction;
        private final PredictionClass mlPrediction;

        public EvaluationRecord(String caseId, String description, PredictionClass groundTruth,
                                PredictionClass rulePrediction, PredictionClass mlPrediction) {
            this.caseId = caseId;
            this.description = description;
            this.groundTruth = groundTruth;
            this.rulePrediction = rulePrediction;
            this.mlPrediction = mlPrediction;
        }

        public String getCaseId() { return caseId; }
        public String getDescription() { return description; }
        public PredictionClass getGroundTruth() { return groundTruth; }
        public PredictionClass getRulePrediction() { return rulePrediction; }
        public PredictionClass getMlPrediction() { return mlPrediction; }

        public boolean isRuleCorrect() { return rulePrediction == groundTruth; }
        public boolean isMlCorrect() { return mlPrediction == groundTruth; }
        public boolean isAgreement() { return rulePrediction == mlPrediction; }

        @Override
        public String toString() {
            return String.format("[%s] Truth: %-10s | Rule: %-10s | ML: %-10s | Desc: %s",
                    caseId, groundTruth, rulePrediction, mlPrediction, description);
        }
    }

    private EvaluationMetrics ruleMetrics;
    private EvaluationMetrics mlMetrics;
    private final List<EvaluationRecord> evaluationHistory = new ArrayList<>();
    private final List<EvaluationRecord> disagreements = new ArrayList<>();

    public DetectionEvaluator() {
        // Default constructor
    }

    /**
     * Evaluates both detectors on labelled Weka test instances.
     * Prevents data leakage by ensuring only the held-out test split is evaluated.
     *
     * @param testInstances labelled test instances from TrainingDataManager
     * @param mlEngine      the trained MLDetectionEngine
     * @param ruleEngine    the active RuleBasedDetectionEngine
     */
    public void evaluateOnTestInstances(Instances testInstances, MLDetectionEngine mlEngine,
                                        RuleBasedDetectionEngine ruleEngine) {
        if (testInstances == null || mlEngine == null || ruleEngine == null) {
            throw new IllegalArgumentException("Evaluation arguments cannot be null.");
        }

        int ruleTP = 0, ruleTN = 0, ruleFP = 0, ruleFN = 0;
        int mlTP = 0, mlTN = 0, mlFP = 0, mlFN = 0;

        for (int i = 0; i < testInstances.numInstances(); i++) {
            Instance inst = testInstances.instance(i);

            // Ground truth label from CSV
            String truthStr = inst.stringValue(inst.classIndex());
            PredictionClass truth = PredictionClass.valueOf(truthStr.toUpperCase());

            // 1. ML Detector prediction
            PredictionClass mlPred;
            try {
                double[] features = new double[cybershield.ml.MLFeatureExtractor.FEATURE_COUNT];
                for (int a = 0; a < cybershield.ml.MLFeatureExtractor.FEATURE_COUNT && a < inst.numAttributes(); a++) {
                    features[a] = inst.value(a);
                }
                ThreatPrediction p = mlEngine.getModel().predict("INST-" + (i + 1), features);
                mlPred = p.getPredictedClass();
            } catch (Exception e) {
                mlPred = PredictionClass.NORMAL;
            }

            // 2. Rule Detector prediction
            // Map test instance features into a simulated SecurityEvent to evaluate rule logic
            double failedLogins = inst.value(0);
            double connectionAttempts = inst.value(1);
            double uniquePorts = inst.value(2);

            AttackType attackType = AttackType.SUSPICIOUS_CONNECTION;
            if (failedLogins >= 5) attackType = AttackType.LOGIN_ATTACK;
            else if (uniquePorts >= 5) attackType = AttackType.PORT_SCAN;

            SecurityEvent syntheticEvent = new SecurityEvent(
                    attackType, "TEST-SRC", "TEST-TGT",
                    "Labelled evaluation instance #" + (i + 1),
                    cybershield.security.Severity.MEDIUM,
                    (int) failedLogins, (int) connectionAttempts, (int) uniquePorts
            );

            List<DetectionResult> ruleResults = ruleEngine.evaluateEvent(syntheticEvent);
            boolean ruleMatched = ruleResults.stream().anyMatch(DetectionResult::isMatched);
            PredictionClass rulePred = ruleMatched ? PredictionClass.SUSPICIOUS : PredictionClass.NORMAL;

            // Update confusion matrix counters
            if (truth == PredictionClass.SUSPICIOUS) {
                if (rulePred == PredictionClass.SUSPICIOUS) ruleTP++; else ruleFN++;
                if (mlPred == PredictionClass.SUSPICIOUS) mlTP++; else mlFN++;
            } else {
                if (rulePred == PredictionClass.SUSPICIOUS) ruleFP++; else ruleTN++;
                if (mlPred == PredictionClass.SUSPICIOUS) mlFP++; else mlTN++;
            }

            EvaluationRecord record = new EvaluationRecord(
                    "INST-" + String.format("%03d", i + 1),
                    String.format("Logins=%.0f, Conns=%.0f, Ports=%.0f", failedLogins, connectionAttempts, uniquePorts),
                    truth, rulePred, mlPred
            );
            evaluationHistory.add(record);

            if (rulePred != mlPred) {
                disagreements.add(record);
            }
        }

        this.ruleMetrics = new EvaluationMetrics("Rule-Based Detection", ruleTP, ruleTN, ruleFP, ruleFN);
        this.mlMetrics = new EvaluationMetrics("Machine Learning Detection", mlTP, mlTN, mlFP, mlFN);
    }

    /**
     * Evaluates simulated attack events with known ground truth tags.
     */
    public void evaluateOnSimulatedEvents(List<SecurityEvent> events, Map<String, PredictionClass> groundTruthMap,
                                         List<ThreatPrediction> mlPredictions, RuleBasedDetectionEngine ruleEngine) {
        if (events == null || groundTruthMap == null || ruleEngine == null) return;

        int ruleTP = 0, ruleTN = 0, ruleFP = 0, ruleFN = 0;
        int mlTP = 0, mlTN = 0, mlFP = 0, mlFN = 0;

        for (SecurityEvent ev : events) {
            PredictionClass truth = groundTruthMap.getOrDefault(ev.getEventId(), PredictionClass.NORMAL);

            // Rule prediction
            List<DetectionResult> ruleMatches = ruleEngine.evaluateEvent(ev);
            PredictionClass rulePred = ruleMatches.stream().anyMatch(DetectionResult::isMatched)
                    ? PredictionClass.SUSPICIOUS : PredictionClass.NORMAL;

            // ML prediction
            PredictionClass mlPred = PredictionClass.NORMAL;
            if (mlPredictions != null) {
                for (ThreatPrediction p : mlPredictions) {
                    if (p.getEventId().equals(ev.getEventId())) {
                        mlPred = p.getPredictedClass();
                        break;
                    }
                }
            }

            if (truth == PredictionClass.SUSPICIOUS) {
                if (rulePred == PredictionClass.SUSPICIOUS) ruleTP++; else ruleFN++;
                if (mlPred == PredictionClass.SUSPICIOUS) mlTP++; else mlFN++;
            } else {
                if (rulePred == PredictionClass.SUSPICIOUS) ruleFP++; else ruleTN++;
                if (mlPred == PredictionClass.SUSPICIOUS) mlFP++; else mlTN++;
            }

            EvaluationRecord rec = new EvaluationRecord(
                    ev.getEventId(), ev.getEventDescription(), truth, rulePred, mlPred
            );
            evaluationHistory.add(rec);
            if (rulePred != mlPred) disagreements.add(rec);
        }

        this.ruleMetrics = new EvaluationMetrics("Rule-Based Detection", ruleTP, ruleTN, ruleFP, ruleFN);
        this.mlMetrics = new EvaluationMetrics("Machine Learning Detection", mlTP, mlTN, mlFP, mlFN);
    }

    public EvaluationMetrics getRuleMetrics() { return ruleMetrics; }
    public EvaluationMetrics getMlMetrics() { return mlMetrics; }
    public List<EvaluationRecord> getEvaluationHistory() { return Collections.unmodifiableList(evaluationHistory); }
    public List<EvaluationRecord> getDisagreements() { return Collections.unmodifiableList(disagreements); }
}
