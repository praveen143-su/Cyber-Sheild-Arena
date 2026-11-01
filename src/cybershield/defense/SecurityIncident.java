package cybershield.defense;

import cybershield.monitoring.SecurityAlert;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SecurityIncident — CyberShield Arena Phase 6
 *
 * OOP Concepts demonstrated:
 *   - Encapsulation : All internal fields are protected and modified via strictly validated methods.
 *   - State Pattern : State transitions follow business rules (cannot mark CONTAINED or RECOVERED
 *                     unless associated defensive actions were verified as successful).
 */
public class SecurityIncident {

    private static final AtomicInteger INCIDENT_ID_GEN = new AtomicInteger(1);

    private final String incidentId;
    private final String primaryAlertId;
    private final String sourceNodeId;
    private final String targetNodeId;
    private final Instant createdAt;
    private IncidentStatus status;
    private Instant resolvedAt;

    private final List<String> associatedAlertIds = new ArrayList<>();
    private final List<String> actionIds = new ArrayList<>();
    private final List<String> auditTimeline = new ArrayList<>();

    public SecurityIncident(SecurityAlert alert) {
        if (alert == null) {
            throw new IllegalArgumentException("Cannot create incident from null alert.");
        }
        this.incidentId = String.format("INC-%04d", INCIDENT_ID_GEN.getAndIncrement());
        this.primaryAlertId = alert.getAlertId();
        this.sourceNodeId = alert.getSourceNodeId();
        this.targetNodeId = alert.getTargetNodeId();
        this.createdAt = Instant.now();
        this.status = IncidentStatus.OPEN;

        this.associatedAlertIds.add(alert.getAlertId());
        addAuditNote("Incident created from Alert " + alert.getAlertId() + " (" + alert.getAlertTitle() + ")");
    }

    public static String nextId() {
        return String.format("INC-%04d", INCIDENT_ID_GEN.get());
    }

    public synchronized void markInvestigating(String note) {
        this.status = IncidentStatus.INVESTIGATING;
        addAuditNote("Status -> INVESTIGATING. " + (note != null ? note : ""));
    }

    /**
     * Transitions incident to CONTAINED only if the defensive action succeeded.
     *
     * @param result the executed DefenseResult
     * @throws IllegalStateException if the action failed
     */
    public synchronized void markContained(DefenseResult result) {
        if (result == null || !result.isSuccess()) {
            throw new IllegalStateException(
                    "Cannot mark incident " + incidentId + " as CONTAINED: Defensive action failed or was rejected. " +
                    (result != null ? result.getFailureReason() : "Null result")
            );
        }
        this.actionIds.add(result.getActionId());
        this.status = IncidentStatus.CONTAINED;
        addAuditNote("Status -> CONTAINED via action " + result.getActionId() + " [" + result.getActionType() + "]");
    }

    /**
     * Transitions incident to RECOVERED only if the recovery action succeeded.
     *
     * @param recoveryResult the executed recovery DefenseResult
     * @throws IllegalStateException if recovery failed
     */
    public synchronized void markRecovered(DefenseResult recoveryResult) {
        if (recoveryResult == null || !recoveryResult.isSuccess()) {
            throw new IllegalStateException(
                    "Cannot mark incident " + incidentId + " as RECOVERED: Recovery action failed or was rejected. " +
                    (recoveryResult != null ? recoveryResult.getFailureReason() : "Null result")
            );
        }
        this.actionIds.add(recoveryResult.getActionId());
        this.status = IncidentStatus.RECOVERED;
        addAuditNote("Status -> RECOVERED via action " + recoveryResult.getActionId() + " [" + recoveryResult.getActionType() + "]");
    }

    public synchronized void close(String closingNote) {
        this.status = IncidentStatus.CLOSED;
        this.resolvedAt = Instant.now();
        addAuditNote("Status -> CLOSED. " + (closingNote != null ? closingNote : "Forensics verified."));
    }

    public synchronized void addAuditNote(String note) {
        if (note != null && !note.trim().isEmpty()) {
            auditTimeline.add(String.format("[%s] %s", Instant.now(), note.trim()));
        }
    }

    public synchronized void associateAlert(String alertId) {
        if (alertId != null && !associatedAlertIds.contains(alertId)) {
            associatedAlertIds.add(alertId);
        }
    }

    // ---------------------------------------------------------------
    // Getters
    // ---------------------------------------------------------------

    public String getIncidentId() { return incidentId; }
    public String getPrimaryAlertId() { return primaryAlertId; }
    public String getSourceNodeId() { return sourceNodeId; }
    public String getTargetNodeId() { return targetNodeId; }
    public Instant getCreatedAt() { return createdAt; }
    public IncidentStatus getStatus() { return status; }
    public Instant getResolvedAt() { return resolvedAt; }
    public List<String> getAssociatedAlertIds() { return Collections.unmodifiableList(associatedAlertIds); }
    public List<String> getActionIds() { return Collections.unmodifiableList(actionIds); }
    public List<String> getAuditTimeline() { return Collections.unmodifiableList(auditTimeline); }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurityIncident that = (SecurityIncident) o;
        return Objects.equals(incidentId, that.incidentId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(incidentId);
    }

    @Override
    public String toString() {
        return String.format("[%s] Status: %-12s | Primary Alert: %-8s | Target: %-8s | Created: %s",
                incidentId, status, primaryAlertId, targetNodeId, createdAt);
    }
}
