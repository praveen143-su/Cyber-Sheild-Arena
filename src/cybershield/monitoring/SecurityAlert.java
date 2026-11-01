package cybershield.monitoring;

import cybershield.security.Severity;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SecurityAlert — CyberShield Arena Phase 4
 *
 * OOP Concepts demonstrated:
 *   - Encapsulation : All fields are private and immutable (final).
 *   - Domain Entity : Represents an actionable security alert raised when a detection rule triggers.
 *   - Defensive Validation: Enforces that risk scores are strictly clamped in [0, 100].
 */
public class SecurityAlert {

    private static final AtomicInteger ALERT_ID_GEN = new AtomicInteger(1);

    private final String alertId;
    private final String eventId;
    private final Instant timestamp;
    private final String sourceNodeId;
    private final String targetNodeId;
    private final String alertTitle;
    private final String explanation;
    private final Severity severity;
    private final int riskScore; // 0 to 100
    private final List<String> associatedRuleIds;

    /**
     * Constructs a SecurityAlert with an auto-generated alert ID and current timestamp.
     */
    public SecurityAlert(String eventId, String sourceNodeId, String targetNodeId,
                         String alertTitle, String explanation, Severity severity,
                         int riskScore, List<String> associatedRuleIds) {
        this(generateAlertId(), eventId, Instant.now(), sourceNodeId, targetNodeId,
                alertTitle, explanation, severity, riskScore, associatedRuleIds);
    }

    /**
     * Full constructor for SecurityAlert.
     */
    public SecurityAlert(String alertId, String eventId, Instant timestamp,
                         String sourceNodeId, String targetNodeId,
                         String alertTitle, String explanation, Severity severity,
                         int riskScore, List<String> associatedRuleIds) {
        if (alertId == null || alertId.trim().isEmpty()) {
            throw new IllegalArgumentException("Alert ID must not be blank.");
        }
        if (eventId == null || eventId.trim().isEmpty()) {
            throw new IllegalArgumentException("Event ID must not be blank.");
        }
        if (timestamp == null) {
            throw new IllegalArgumentException("Timestamp must not be null.");
        }
        if (sourceNodeId == null || sourceNodeId.trim().isEmpty()) {
            throw new IllegalArgumentException("Source Node ID must not be blank.");
        }
        if (targetNodeId == null || targetNodeId.trim().isEmpty()) {
            throw new IllegalArgumentException("Target Node ID must not be blank.");
        }
        if (alertTitle == null || alertTitle.trim().isEmpty()) {
            throw new IllegalArgumentException("Alert title must not be blank.");
        }
        if (explanation == null || explanation.trim().isEmpty()) {
            throw new IllegalArgumentException("Explanation must not be blank.");
        }
        if (severity == null) {
            throw new IllegalArgumentException("Severity must not be null.");
        }
        if (riskScore < 0 || riskScore > 100) {
            throw new IllegalArgumentException("Risk score must be between 0 and 100 (received: " + riskScore + ").");
        }

        this.alertId = alertId.trim();
        this.eventId = eventId.trim();
        this.timestamp = timestamp;
        this.sourceNodeId = sourceNodeId.trim();
        this.targetNodeId = targetNodeId.trim();
        this.alertTitle = alertTitle.trim();
        this.explanation = explanation.trim();
        this.severity = severity;
        this.riskScore = riskScore;
        this.associatedRuleIds = (associatedRuleIds != null)
                ? Collections.unmodifiableList(new ArrayList<>(associatedRuleIds))
                : Collections.emptyList();
    }

    private static String generateAlertId() {
        return String.format("ALT-%04d", ALERT_ID_GEN.getAndIncrement());
    }

    // ---------------------------------------------------------------
    // Getters
    // ---------------------------------------------------------------

    public String getAlertId() {
        return alertId;
    }

    public String getEventId() {
        return eventId;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getSourceNodeId() {
        return sourceNodeId;
    }

    public String getTargetNodeId() {
        return targetNodeId;
    }

    public String getAlertTitle() {
        return alertTitle;
    }

    public String getExplanation() {
        return explanation;
    }

    public Severity getSeverity() {
        return severity;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public List<String> getAssociatedRuleIds() {
        return associatedRuleIds;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurityAlert that = (SecurityAlert) o;
        return Objects.equals(alertId, that.alertId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(alertId);
    }

    @Override
    public String toString() {
        return String.format("[%s] Event: %s | Title: \"%s\" | Severity: %s | Score: %d/100 | Target: %s | Rules: %s",
                alertId, eventId, alertTitle, severity, riskScore, targetNodeId, associatedRuleIds);
    }
}
