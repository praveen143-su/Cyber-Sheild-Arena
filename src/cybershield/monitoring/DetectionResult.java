package cybershield.monitoring;

import cybershield.security.Severity;

import java.util.Objects;

/**
 * DetectionResult — CyberShield Arena Phase 4
 *
 * OOP Concepts demonstrated:
 *   - Value Object  : Immutable result produced by a DetectionRule evaluation.
 *   - Encapsulation : Private final fields with validated accessors.
 *
 * Encapsulates whether a detection rule matched an event, along with the reasoning,
 * recommended severity rating, and forensic evidence.
 */
public class DetectionResult {

    private final String ruleId;
    private final boolean matched;
    private final String explanation;
    private final Severity recommendedSeverity;
    private final String evidence;

    /**
     * Constructs a DetectionResult.
     *
     * @param ruleId              unique identifier of the evaluating rule
     * @param matched             true if the rule criteria were satisfied
     * @param explanation         human-readable rationale for match or non-match
     * @param recommendedSeverity recommended severity level if matched (or default severity if not)
     * @param evidence            specific metric values or details that triggered the evaluation
     */
    public DetectionResult(String ruleId, boolean matched, String explanation,
                           Severity recommendedSeverity, String evidence) {
        if (ruleId == null || ruleId.trim().isEmpty()) {
            throw new IllegalArgumentException("Rule ID cannot be blank in DetectionResult.");
        }
        if (explanation == null || explanation.trim().isEmpty()) {
            throw new IllegalArgumentException("Explanation cannot be blank in DetectionResult.");
        }
        if (recommendedSeverity == null) {
            throw new IllegalArgumentException("Recommended severity cannot be null in DetectionResult.");
        }

        this.ruleId = ruleId.trim();
        this.matched = matched;
        this.explanation = explanation.trim();
        this.recommendedSeverity = recommendedSeverity;
        this.evidence = (evidence != null) ? evidence.trim() : "None";
    }

    /**
     * Helper factory for creating a non-matching result.
     */
    public static DetectionResult noMatch(String ruleId, String explanation) {
        return new DetectionResult(ruleId, false, explanation, Severity.LOW, "None");
    }

    // ---------------------------------------------------------------
    // Getters
    // ---------------------------------------------------------------

    public String getRuleId() {
        return ruleId;
    }

    public boolean isMatched() {
        return matched;
    }

    public String getExplanation() {
        return explanation;
    }

    public Severity getRecommendedSeverity() {
        return recommendedSeverity;
    }

    public String getEvidence() {
        return evidence;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DetectionResult that = (DetectionResult) o;
        return matched == that.matched &&
                Objects.equals(ruleId, that.ruleId) &&
                Objects.equals(explanation, that.explanation);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ruleId, matched, explanation);
    }

    @Override
    public String toString() {
        return String.format("[Rule: %s | Match: %s | Severity: %s | Evidence: %s | Reason: \"%s\"]",
                ruleId, matched, recommendedSeverity, evidence, explanation);
    }
}
