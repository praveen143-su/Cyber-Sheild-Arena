package cybershield.monitoring;

import cybershield.security.AttackType;
import cybershield.security.FirewallAction;
import cybershield.security.SecurityEvent;
import cybershield.security.Severity;

/**
 * SuspiciousConnectionRule — CyberShield Arena Phase 4
 *
 * OOP Concepts demonstrated:
 *   - Interface Realization : Implements DetectionRule.
 *   - Contextual Analysis   : Differentiates between routine firewall drops and genuine threats.
 *   - Defense in Depth      : Validates both policy disposition and traffic anomaly volume.
 *
 * Core Cybersecurity Principle:
 *   Firewall denial != confirmed malicious breach.
 *   A standard blocked connection is normal perimeter defense. This rule generates an alert
 *   ONLY when suspicious traffic actively penetrated the perimeter (ALLOW with high volume)
 *   or when sustained aggressive probing exceeds the persistent probing threshold.
 */
public class SuspiciousConnectionRule implements DetectionRule {

    public static final String DEFAULT_RULE_ID = "RULE-SC-01";
    public static final int DEFAULT_ACTIVE_BREACH_THRESHOLD = 5;
    public static final int DEFAULT_PERSISTENT_PROBE_THRESHOLD = 10;

    private final String ruleId;
    private final int activeBreachThreshold;
    private final int persistentProbeThreshold;

    public SuspiciousConnectionRule() {
        this(DEFAULT_RULE_ID, DEFAULT_ACTIVE_BREACH_THRESHOLD, DEFAULT_PERSISTENT_PROBE_THRESHOLD);
    }

    public SuspiciousConnectionRule(int activeBreachThreshold, int persistentProbeThreshold) {
        this(DEFAULT_RULE_ID, activeBreachThreshold, persistentProbeThreshold);
    }

    public SuspiciousConnectionRule(String ruleId, int activeBreachThreshold, int persistentProbeThreshold) {
        if (ruleId == null || ruleId.trim().isEmpty()) {
            throw new IllegalArgumentException("Rule ID cannot be blank.");
        }
        if (activeBreachThreshold <= 0) {
            throw new IllegalArgumentException("Active breach threshold must be greater than zero.");
        }
        if (persistentProbeThreshold <= 0) {
            throw new IllegalArgumentException("Persistent probe threshold must be greater than zero.");
        }
        this.ruleId = ruleId.trim();
        this.activeBreachThreshold = activeBreachThreshold;
        this.persistentProbeThreshold = persistentProbeThreshold;
    }

    @Override
    public String getRuleId() {
        return ruleId;
    }

    @Override
    public String getRuleDescription() {
        return "Detects uncontained suspicious connections (Active traffic >= " +
                activeBreachThreshold + " attempts) or persistent firewall evasion (Blocked traffic >= " +
                persistentProbeThreshold + " attempts). Does not flag isolated routine drops.";
    }

    @Override
    public DetectionResult evaluate(SecurityEvent event) {
        if (event == null) {
            return DetectionResult.noMatch(ruleId, "Event is null");
        }

        if (event.getAttackType() != AttackType.SUSPICIOUS_CONNECTION) {
            return DetectionResult.noMatch(ruleId, "Event is not of type SUSPICIOUS_CONNECTION.");
        }

        int attempts = event.getConnectionAttemptCount();
        FirewallAction fwAction = event.getFirewallAction().orElse(null);

        // Case 1: Active uncontained connection flowing through firewall with high volume
        if (fwAction == FirewallAction.ALLOW && attempts >= activeBreachThreshold) {
            String reason = String.format(
                    "Active suspicious connection detected: %d attempts from %s to %s permitted by firewall. Uncontained anomaly.",
                    attempts, event.getSourceNodeId(), event.getTargetNodeId());
            String evidence = String.format("firewallAction=ALLOW, connectionAttemptCount=%d, threshold=%d, status=ACTIVE",
                    attempts, activeBreachThreshold);
            return new DetectionResult(ruleId, true, reason, Severity.HIGH, evidence);
        }

        // Case 2: Sustained, aggressive traversal attempts (even though blocked, volume indicates brute-force network probing)
        if (fwAction == FirewallAction.BLOCK && attempts >= persistentProbeThreshold) {
            String reason = String.format(
                    "Persistent perimeter evasion detected: %d repeated blocked attempts from %s to %s exceeds persistent probing threshold (%d).",
                    attempts, event.getSourceNodeId(), event.getTargetNodeId(), persistentProbeThreshold);
            String evidence = String.format("firewallAction=BLOCK, connectionAttemptCount=%d, threshold=%d, status=REPEATED_PROBES",
                    attempts, persistentProbeThreshold);
            return new DetectionResult(ruleId, true, reason, Severity.HIGH, evidence);
        }

        // Routine firewall block or low volume: DO NOT infer malicious breach
        if (fwAction == FirewallAction.BLOCK) {
            return DetectionResult.noMatch(ruleId, String.format(
                    "Routine firewall containment: %d connection attempts blocked. Normal defense operation; no breach alert generated.",
                    attempts));
        }

        return DetectionResult.noMatch(ruleId, String.format(
                "Connection attempt count (%d) did not meet active breach threshold (%d).",
                attempts, activeBreachThreshold));
    }

    public int getActiveBreachThreshold() {
        return activeBreachThreshold;
    }

    public int getPersistentProbeThreshold() {
        return persistentProbeThreshold;
    }
}
