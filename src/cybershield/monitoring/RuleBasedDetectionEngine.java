package cybershield.monitoring;

import cybershield.security.SecurityEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * RuleBasedDetectionEngine — CyberShield Arena Phase 4
 *
 * OOP Concepts demonstrated:
 *   - Polymorphism / Strategy : Evaluates diverse DetectionRule implementations uniformly.
 *   - Open/Closed Principle   : New threat rules can be added dynamically without touching this engine.
 *   - Encapsulation           : Registered rules and evaluation routines are safely managed.
 */
public class RuleBasedDetectionEngine {

    private final Map<String, DetectionRule> registeredRules = new LinkedHashMap<>();

    public RuleBasedDetectionEngine() {
        // Default constructor
    }

    /**
     * Registers a new detection rule into the engine.
     *
     * @param rule the DetectionRule implementation to add
     */
    public void registerRule(DetectionRule rule) {
        if (rule == null) {
            throw new IllegalArgumentException("Detection rule cannot be null.");
        }
        registeredRules.put(rule.getRuleId(), rule);
        System.out.println("[DetectionEngine] Registered Rule: " + rule.getRuleId() + " : " + rule.getRuleDescription());
    }

    /**
     * Removes a rule by its rule ID.
     *
     * @param ruleId ID of rule to remove
     * @return true if found and removed
     */
    public boolean removeRule(String ruleId) {
        if (ruleId == null) return false;
        return registeredRules.remove(ruleId.trim()) != null;
    }

    /**
     * Evaluates a security event against all registered rules.
     * Collects and returns only the matching DetectionResult instances.
     *
     * @param event the SecurityEvent to inspect
     * @return List of matching DetectionResults (empty if no rules matched)
     */
    public List<DetectionResult> evaluateEvent(SecurityEvent event) {
        if (event == null) {
            return Collections.emptyList();
        }

        List<DetectionResult> matchedResults = new ArrayList<>();
        for (DetectionRule rule : registeredRules.values()) {
            try {
                DetectionResult result = rule.evaluate(event);
                if (result != null && result.isMatched()) {
                    matchedResults.add(result);
                }
            } catch (Exception e) {
                System.err.printf("[DetectionEngine] Error executing rule '%s': %s\n",
                        rule.getRuleId(), e.getMessage());
            }
        }

        return matchedResults;
    }

    /**
     * Returns an unmodifiable list of all registered rules.
     */
    public List<DetectionRule> getRegisteredRules() {
        return Collections.unmodifiableList(new ArrayList<>(registeredRules.values()));
    }

    public int getRuleCount() {
        return registeredRules.size();
    }
}
