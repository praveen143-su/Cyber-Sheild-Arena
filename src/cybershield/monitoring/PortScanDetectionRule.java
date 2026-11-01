package cybershield.monitoring;

import cybershield.security.SecurityEvent;
import cybershield.security.Severity;

/**
 * PortScanDetectionRule — CyberShield Arena Phase 4
 *
 * OOP Concepts demonstrated:
 *   - Interface Realization : Implements DetectionRule.
 *   - Threshold Parameterization: Configurable port and connection thresholds.
 *   - Forensic Evidence Formatting: Packages key event telemetry into DetectionResult.
 *
 * Identifies port reconnaissance sweeps targeting multiple destination ports.
 */
public class PortScanDetectionRule implements DetectionRule {

    public static final String DEFAULT_RULE_ID = "RULE-PS-01";
    public static final int DEFAULT_PORT_THRESHOLD = 10;
    public static final int DEFAULT_MIN_CONNECTION_ATTEMPTS = 5;

    private final String ruleId;
    private final int uniquePortThreshold;
    private final int minConnectionAttempts;

    public PortScanDetectionRule() {
        this(DEFAULT_RULE_ID, DEFAULT_PORT_THRESHOLD, DEFAULT_MIN_CONNECTION_ATTEMPTS);
    }

    public PortScanDetectionRule(int uniquePortThreshold) {
        this(DEFAULT_RULE_ID, uniquePortThreshold, DEFAULT_MIN_CONNECTION_ATTEMPTS);
    }

    public PortScanDetectionRule(int uniquePortThreshold, int minConnectionAttempts) {
        this(DEFAULT_RULE_ID, uniquePortThreshold, minConnectionAttempts);
    }

    public PortScanDetectionRule(String ruleId, int uniquePortThreshold, int minConnectionAttempts) {
        if (ruleId == null || ruleId.trim().isEmpty()) {
            throw new IllegalArgumentException("Rule ID cannot be blank.");
        }
        if (uniquePortThreshold <= 0) {
            throw new IllegalArgumentException("Unique port threshold must be greater than zero.");
        }
        if (minConnectionAttempts < 0) {
            throw new IllegalArgumentException("Min connection attempts cannot be negative.");
        }
        this.ruleId = ruleId.trim();
        this.uniquePortThreshold = uniquePortThreshold;
        this.minConnectionAttempts = minConnectionAttempts;
    }

    @Override
    public String getRuleId() {
        return ruleId;
    }

    @Override
    public String getRuleDescription() {
        return "Detects reconnaissance port sweeping (Threshold: >= " +
                uniquePortThreshold + " unique ports and >= " + minConnectionAttempts + " connection attempts)";
    }

    @Override
    public DetectionResult evaluate(SecurityEvent event) {
        if (event == null) {
            return DetectionResult.noMatch(ruleId, "Event is null");
        }

        int uniquePorts = event.getUniquePortCount();
        int attempts = event.getConnectionAttemptCount();

        // Check if both port threshold and minimum connection attempts are met
        if (uniquePorts >= uniquePortThreshold && attempts >= minConnectionAttempts) {
            Severity recommendedSev = (uniquePorts >= uniquePortThreshold * 2) ? Severity.HIGH : Severity.MEDIUM;
            String reason = String.format(
                    "Port reconnaissance pattern detected: %d unique ports probed across %d connection attempts from %s to %s.",
                    uniquePorts, attempts, event.getSourceNodeId(), event.getTargetNodeId());
            String evidence = String.format("uniquePortCount=%d, connectionAttemptCount=%d, thresholds=[ports:%d, conns:%d]",
                    uniquePorts, attempts, uniquePortThreshold, minConnectionAttempts);

            return new DetectionResult(ruleId, true, reason, recommendedSev, evidence);
        }

        return DetectionResult.noMatch(ruleId, String.format(
                "Port metrics (ports: %d, conns: %d) did not satisfy thresholds (ports: %d, conns: %d).",
                uniquePorts, attempts, uniquePortThreshold, minConnectionAttempts));
    }

    public int getUniquePortThreshold() {
        return uniquePortThreshold;
    }

    public int getMinConnectionAttempts() {
        return minConnectionAttempts;
    }
}
