package cybershield.defense;

import cybershield.ml.PredictionClass;
import cybershield.ml.ThreatPrediction;
import cybershield.monitoring.SecurityAlert;
import cybershield.security.Severity;

/**
 * DefensePolicy — CyberShield Arena Phase 6
 *
 * OOP Concepts demonstrated:
 *   - Encapsulation     : Configurable risk thresholds and policy modes.
 *   - Decision Object   : Inner PolicyDecision structure returns decision + explainable reasoning.
 *   - Evidence Weighting: Corroborates rule-based RiskScore with ML ThreatPrediction.
 *                         Never treats ML as infallible; handles missing or low-confidence ML gracefully.
 */
public class DefensePolicy {

    public static final int DEFAULT_LOW_THRESHOLD = 40;
    public static final int DEFAULT_MEDIUM_THRESHOLD = 65;
    public static final int DEFAULT_HIGH_THRESHOLD = 85;
    public static final double DEFAULT_ML_CONFIDENCE_THRESHOLD = 0.70;

    private int lowRiskThreshold;
    private int mediumRiskThreshold;
    private int highRiskThreshold;
    private double mlConfidenceThreshold;
    private boolean alertOnlyMode;
    private boolean requireApprovalForIsolation;

    /**
     * Inner class encapsulating the policy evaluation output.
     */
    public static class PolicyDecision {
        private final DefenseActionType recommendedAction;
        private final String rationale;
        private final boolean requiresManualApproval;

        public PolicyDecision(DefenseActionType recommendedAction, String rationale, boolean requiresManualApproval) {
            this.recommendedAction = recommendedAction;
            this.rationale = rationale;
            this.requiresManualApproval = requiresManualApproval;
        }

        public DefenseActionType getRecommendedAction() { return recommendedAction; }
        public String getRationale() { return rationale; }
        public boolean isRequiresManualApproval() { return requiresManualApproval; }

        @Override
        public String toString() {
            return String.format("[%s] %s%s",
                    recommendedAction, rationale,
                    (requiresManualApproval ? " (MANUAL APPROVAL REQUIRED)" : ""));
        }
    }

    public DefensePolicy() {
        this(DEFAULT_LOW_THRESHOLD, DEFAULT_MEDIUM_THRESHOLD, DEFAULT_HIGH_THRESHOLD,
             DEFAULT_ML_CONFIDENCE_THRESHOLD, false, false);
    }

    public DefensePolicy(int lowRiskThreshold, int mediumRiskThreshold, int highRiskThreshold,
                         double mlConfidenceThreshold, boolean alertOnlyMode, boolean requireApprovalForIsolation) {
        setThresholds(lowRiskThreshold, mediumRiskThreshold, highRiskThreshold);
        setMlConfidenceThreshold(mlConfidenceThreshold);
        this.alertOnlyMode = alertOnlyMode;
        this.requireApprovalForIsolation = requireApprovalForIsolation;
    }

    /**
     * Evaluates a security alert alongside optional ML prediction to determine the appropriate response.
     *
     * @param alert        the triggered SecurityAlert from Phase 4
     * @param mlPrediction optional ThreatPrediction from Phase 5 (may be null)
     * @return PolicyDecision containing action, explanation, and approval status
     */
    public PolicyDecision evaluate(SecurityAlert alert, ThreatPrediction mlPrediction) {
        if (alert == null) {
            return new PolicyDecision(DefenseActionType.ALERT_ONLY, "No alert provided.", false);
        }

        // Global Alert-Only Mode check
        if (alertOnlyMode) {
            return new PolicyDecision(
                    DefenseActionType.ALERT_ONLY,
                    "System configured in ALERT_ONLY mode. Network changes suppressed.",
                    false
            );
        }

        int score = alert.getRiskScore();
        Severity severity = alert.getSeverity();

        // Analyze ML prediction evidence
        boolean mlAvailable = (mlPrediction != null);
        boolean mlSuspicious = mlAvailable && mlPrediction.getPredictedClass() == PredictionClass.SUSPICIOUS;
        boolean mlHighConfidence = mlAvailable && mlPrediction.getConfidenceScore() >= mlConfidenceThreshold;

        // Evidence summary for audit and explanation
        String evidence;
        if (mlAvailable) {
            evidence = String.format("Risk Score: %d/100, Severity: %s, ML: %s (%.1f%% confidence)",
                    score, severity, mlPrediction.getPredictedClass(), mlPrediction.getConfidenceScore() * 100);
        } else {
            evidence = String.format("Risk Score: %d/100, Severity: %s, ML: Unavailable (Rule-based fallback)",
                    score, severity);
        }

        // Policy Evaluation Matrix

        // Level 1: Critical Risk / Severe Compromise -> Consider Isolation
        if (severity == Severity.CRITICAL || (score >= 90 && mlSuspicious && mlHighConfidence)) {
            if (requireApprovalForIsolation) {
                return new PolicyDecision(
                        DefenseActionType.ISOLATE_DEVICE,
                        evidence + " -> Critical threat warrants device isolation; requires operator approval.",
                        true
                );
            }
            return new PolicyDecision(
                    DefenseActionType.ISOLATE_DEVICE,
                    evidence + " -> Critical threat with corroborated evidence; isolating device.",
                    false
            );
        }

        // Level 2: High Risk (> 85) -> Block Connection or Temporary Block
        if (score >= highRiskThreshold) {
            if (mlSuspicious && mlHighConfidence) {
                return new PolicyDecision(
                        DefenseActionType.BLOCK_CONNECTION,
                        evidence + " -> Elevated high risk confirmed by ML model; blocking connection.",
                        false
                );
            }
            return new PolicyDecision(
                    DefenseActionType.TEMPORARY_BLOCK,
                    evidence + " -> High risk detected; enforcing temporary block.",
                    false
            );
        }

        // Level 3: Medium-High Risk (65 - 84) -> Temporary Block
        if (score >= mediumRiskThreshold || severity == Severity.HIGH || severity == Severity.MEDIUM) {
            return new PolicyDecision(
                    DefenseActionType.TEMPORARY_BLOCK,
                    evidence + " -> Elevated risk and repeated simulated activity; enforcing temporary block.",
                    false
            );
        }

        // Level 3: Low-Medium Risk -> Temporary Block
        if (score >= lowRiskThreshold || severity == Severity.MEDIUM) {
            return new PolicyDecision(
                    DefenseActionType.TEMPORARY_BLOCK,
                    evidence + " -> Moderate risk; applying temporary block.",
                    false
            );
        }

        // Level 4: Low Risk -> Alert Only
        return new PolicyDecision(
                DefenseActionType.ALERT_ONLY,
                evidence + " -> Low risk; recording alert without active disruption.",
                false
        );
    }

    // ---------------------------------------------------------------
    // Configuration Setters & Getters
    // ---------------------------------------------------------------

    public void setThresholds(int low, int medium, int high) {
        if (low < 0 || low >= medium || medium >= high || high > 100) {
            throw new IllegalArgumentException(
                    "Invalid thresholds: must satisfy 0 <= low < medium < high <= 100 " +
                    "(got " + low + ", " + medium + ", " + high + ")."
            );
        }
        this.lowRiskThreshold = low;
        this.mediumRiskThreshold = medium;
        this.highRiskThreshold = high;
    }

    public void setMlConfidenceThreshold(double threshold) {
        if (threshold < 0.0 || threshold > 1.0) {
            throw new IllegalArgumentException("ML confidence threshold must be in [0.0, 1.0].");
        }
        this.mlConfidenceThreshold = threshold;
    }

    public int getLowRiskThreshold() { return lowRiskThreshold; }
    public int getMediumRiskThreshold() { return mediumRiskThreshold; }
    public int getHighRiskThreshold() { return highRiskThreshold; }
    public double getMlConfidenceThreshold() { return mlConfidenceThreshold; }
    public boolean isAlertOnlyMode() { return alertOnlyMode; }
    public void setAlertOnlyMode(boolean alertOnlyMode) { this.alertOnlyMode = alertOnlyMode; }
    public boolean isRequireApprovalForIsolation() { return requireApprovalForIsolation; }
    public void setRequireApprovalForIsolation(boolean require) { this.requireApprovalForIsolation = require; }
}
