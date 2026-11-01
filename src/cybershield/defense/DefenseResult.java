package cybershield.defense;

import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * DefenseResult — CyberShield Arena Phase 6
 *
 * OOP Concepts demonstrated:
 *   - Encapsulation : All fields are private and immutable (final).
 *   - Value Object  : Represents the immutable outcome of an executed defense strategy.
 *   - Factory Pattern: Static factory methods (success, failure) simplify caller construction.
 *   - Defensive Programming: Validates mandatory parameters (actionType, targetId, timestamp).
 */
public class DefenseResult {

    private static final AtomicInteger ACTION_ID_GEN = new AtomicInteger(1);

    private final String actionId;
    private final DefenseActionType actionType;
    private final String alertId;             // Optional: associated SecurityAlert ID
    private final String targetId;            // Target node ID or connection ID
    private final boolean success;
    private final String resultDescription;
    private final Instant timestamp;
    private final String failureReason;       // Null or explanatory message if failed

    /**
     * Full constructor with explicit parameters.
     */
    public DefenseResult(String actionId, DefenseActionType actionType, String alertId,
                         String targetId, boolean success, String resultDescription,
                         Instant timestamp, String failureReason) {
        if (actionId == null || actionId.trim().isEmpty()) {
            throw new IllegalArgumentException("Action ID must not be blank.");
        }
        if (actionType == null) {
            throw new IllegalArgumentException("Defense action type cannot be null.");
        }
        if (targetId == null || targetId.trim().isEmpty()) {
            throw new IllegalArgumentException("Target ID must not be blank.");
        }
        if (resultDescription == null || resultDescription.trim().isEmpty()) {
            throw new IllegalArgumentException("Result description must not be blank.");
        }
        if (timestamp == null) {
            throw new IllegalArgumentException("Timestamp must not be null.");
        }

        this.actionId = actionId.trim();
        this.actionType = actionType;
        this.alertId = (alertId != null && !alertId.trim().isEmpty()) ? alertId.trim() : "N/A";
        this.targetId = targetId.trim();
        this.success = success;
        this.resultDescription = resultDescription.trim();
        this.timestamp = timestamp;
        this.failureReason = (failureReason != null && !failureReason.trim().isEmpty())
                ? failureReason.trim() : null;
    }

    /**
     * Generates a new unique sequential action identifier (e.g., "ACT-0001").
     */
    public static String generateActionId() {
        return String.format("ACT-%04d", ACTION_ID_GEN.getAndIncrement());
    }

    /**
     * Factory method for creating a successful DefenseResult.
     */
    public static DefenseResult success(DefenseActionType actionType, String alertId,
                                        String targetId, String description) {
        return new DefenseResult(
                generateActionId(),
                actionType,
                alertId,
                targetId,
                true,
                description,
                Instant.now(),
                null
        );
    }

    /**
     * Factory method for creating a failed DefenseResult.
     */
    public static DefenseResult failure(DefenseActionType actionType, String alertId,
                                        String targetId, String description, String failureReason) {
        return new DefenseResult(
                generateActionId(),
                actionType,
                alertId,
                targetId,
                false,
                description,
                Instant.now(),
                failureReason
        );
    }

    // ---------------------------------------------------------------
    // Getters
    // ---------------------------------------------------------------

    public String getActionId() {
        return actionId;
    }

    public DefenseActionType getActionType() {
        return actionType;
    }

    public String getAlertId() {
        return alertId;
    }

    public String getTargetId() {
        return targetId;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getResultDescription() {
        return resultDescription;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getFailureReason() {
        return failureReason;
    }

    // ---------------------------------------------------------------
    // Object Overrides
    // ---------------------------------------------------------------

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DefenseResult that = (DefenseResult) o;
        return Objects.equals(actionId, that.actionId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(actionId);
    }

    @Override
    public String toString() {
        return String.format("[%s] Action: %-15s | Alert: %-8s | Target: %-8s | Success: %-5s | %s%s",
                actionId,
                actionType.name(),
                alertId,
                targetId,
                success,
                resultDescription,
                (failureReason != null ? " [Reason: " + failureReason + "]" : ""));
    }
}
