package cybershield.monitoring;

import cybershield.security.SecurityEvent;

/**
 * DetectionRule Interface — CyberShield Arena Phase 4
 *
 * OOP Concepts demonstrated:
 *   - Interface / Strategy Pattern: Defines the contract for all rule-based detection logic.
 *                                   New detection policies can be added modularly without altering
 *                                   the detection engine (Open/Closed Principle).
 *   - Pure Query                  : Rules evaluate events and return immutable DetectionResults
 *                                   without mutating network devices or system state (Side-effect free).
 */
public interface DetectionRule {

    /**
     * Unique identifier for this rule (e.g. "RULE-BRUTE-FORCE-01").
     *
     * @return rule ID string
     */
    String getRuleId();

    /**
     * Human-readable description of what threat pattern this rule detects.
     *
     * @return rule description
     */
    String getRuleDescription();

    /**
     * Evaluates a security event against the rule's criteria.
     *
     * @param event the SecurityEvent to inspect
     * @return DetectionResult containing match status, rationale, and recommended severity
     */
    DetectionResult evaluate(SecurityEvent event);
}
