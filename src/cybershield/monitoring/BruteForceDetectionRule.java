package cybershield.monitoring;

import cybershield.security.AttackType;
import cybershield.security.SecurityEvent;
import cybershield.security.Severity;

/**
 * BruteForceDetectionRule — CyberShield Arena Phase 4
 *
 * OOP Concepts demonstrated:
 *   - Interface Realization : Implements DetectionRule.
 *   - Configurable State    : Threshold is passed at construction rather than hardcoded.
 *   - Explainability        : Returns structured explanations detailing why the threshold was crossed.
 *
 * Inspects security events for repeated failed authentication attempts exceeding a configured threshold.
 */
public class BruteForceDetectionRule implements DetectionRule {

    public static final String DEFAULT_RULE_ID = "RULE-BF-01";
    public static final int DEFAULT_THRESHOLD = 10;

    private final String ruleId;
    private final int failedLoginThreshold;

    public BruteForceDetectionRule() {
        this(DEFAULT_RULE_ID, DEFAULT_THRESHOLD);
    }

    public BruteForceDetectionRule(int failedLoginThreshold) {
        this(DEFAULT_RULE_ID, failedLoginThreshold);
    }

    public BruteForceDetectionRule(String ruleId, int failedLoginThreshold) {
        if (ruleId == null || ruleId.trim().isEmpty()) {
            throw new IllegalArgumentException("Rule ID cannot be blank.");
        }
        if (failedLoginThreshold <= 0) {
            throw new IllegalArgumentException("Failed login threshold must be greater than zero.");
        }
        this.ruleId = ruleId.trim();
        this.failedLoginThreshold = failedLoginThreshold;
    }

    @Override
    public String getRuleId() {
        return ruleId;
    }

    @Override
    public String getRuleDescription() {
        return "Detects potential brute-force or credential stuffing attacks (Threshold: >= " +
                failedLoginThreshold + " failed logins)";
    }

    @Override
    public DetectionResult evaluate(SecurityEvent event) {
        if (event == null) {
            return DetectionResult.noMatch(ruleId, "Event is null");
        }

        int failedLogins = event.getFailedLoginCount();
        if (failedLogins >= failedLoginThreshold) {
            Severity recommendedSev = (failedLogins >= failedLoginThreshold * 2) ? Severity.CRITICAL : Severity.HIGH;
            String reason = String.format(
                    "Brute-force authentication pattern confirmed: %d failed logins from %s targeting %s (threshold: %d).",
                    failedLogins, event.getSourceNodeId(), event.getTargetNodeId(), failedLoginThreshold);
            String evidence = String.format("failedLoginCount=%d, threshold=%d, target=%s",
                    failedLogins, failedLoginThreshold, event.getTargetNodeId());

            return new DetectionResult(ruleId, true, reason, recommendedSev, evidence);
        }

        return DetectionResult.noMatch(ruleId, String.format(
                "Failed login count (%d) did not meet threshold (%d).", failedLogins, failedLoginThreshold));
    }

    public int getFailedLoginThreshold() {
        return failedLoginThreshold;
    }
}
