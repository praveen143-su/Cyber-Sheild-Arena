package cybershield.defense;

/**
 * IncidentStatus — CyberShield Arena Phase 6
 *
 * OOP Concept: Enum (State Lifecycle)
 * Purpose    : Represents the state of a security incident through its response lifecycle.
 *
 * Lifecycle Progression:
 *   OPEN -> INVESTIGATING -> CONTAINED -> RECOVERED -> CLOSED
 */
public enum IncidentStatus {

    /**
     * Freshly registered incident triggered by an ingested alert.
     */
    OPEN("Open"),

    /**
     * Incident actively undergoing automated or human triage and policy evaluation.
     */
    INVESTIGATING("Investigating"),

    /**
     * Threat neutralized or blocked via successful automated defensive action.
     */
    CONTAINED("Contained"),

    /**
     * Network services or isolated devices safely restored after successful verification.
     */
    RECOVERED("Recovered"),

    /**
     * Post-incident forensics complete, audit finalized, incident archived.
     */
    CLOSED("Closed");

    private final String label;

    IncidentStatus(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    @Override
    public String toString() {
        return label;
    }
}
