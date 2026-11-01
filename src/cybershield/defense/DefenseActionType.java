package cybershield.defense;

/**
 * DefenseActionType — CyberShield Arena Phase 6
 *
 * OOP Concept: Enum (Enumeration)
 * Purpose    : Categorizes the permitted incident response actions executed by the
 *              automated defense subsystem against virtual network threats.
 *
 * Using an enum guarantees type safety, eliminates magic strings, and makes
 * policy-to-action mappings exhaustive and verifiable.
 */
public enum DefenseActionType {

    /**
     * Passive response: Record the alert, notify administrators, and monitor activity
     * without modifying virtual network topology or firewall rules.
     */
    ALERT_ONLY("Alert Only", "Passive monitoring and notification without network modifications"),

    /**
     * Active response: Permanently blocks a simulated connection or injects a high-priority
     * firewall drop rule between the communicating endpoints.
     */
    BLOCK_CONNECTION("Block Connection", "Permanently blocks simulated connection or injects blocking firewall rule"),

    /**
     * Active response: Imposes a time-bounded block on a simulated connection, after which
     * connectivity may be evaluated and restored.
     */
    TEMPORARY_BLOCK("Temporary Block", "Applies a time-bounded block that can expire"),

    /**
     * High-impact active response: Quarantines a device, dropping existing connections
     * and rejecting any subsequent communication attempts to/from the device.
     */
    ISOLATE_DEVICE("Isolate Device", "Completely isolates a virtual node from network communications"),

    /**
     * Remediation response: Restores an isolated device back to normal network operations,
     * maintaining independent baseline firewall policies.
     */
    RESTORE_DEVICE("Restore Device", "Restores an isolated node to operational network access");

    private final String displayName;
    private final String description;

    DefenseActionType(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
