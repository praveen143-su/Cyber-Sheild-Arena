package cybershield.network;

/**
 * ConnectionStatus Enum — CyberShield Arena Phase 2
 *
 * OOP Concept: Enum (Enumeration)
 * Purpose    : Represents the state of a simulated virtual network connection.
 *              Guarantees type-safety and eliminates magic strings or integers.
 *
 * Values:
 *   ACTIVE       — Connection is established and passing network traffic.
 *   BLOCKED      — Connection is intercepted/blocked by firewall policy or security control.
 *   DISCONNECTED — Connection was terminated or dropped.
 */
public enum ConnectionStatus {

    ACTIVE("Active", "Traffic flowing normally"),
    BLOCKED("Blocked", "Blocked by security policy or firewall"),
    DISCONNECTED("Disconnected", "Terminated or inactive connection");

    private final String displayLabel;
    private final String description;

    ConnectionStatus(String displayLabel, String description) {
        this.displayLabel = displayLabel;
        this.description = description;
    }

    public String getDisplayLabel() {
        return displayLabel;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return displayLabel;
    }
}
