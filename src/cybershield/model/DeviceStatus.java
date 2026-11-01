package cybershield.model;

/**
 * DeviceStatus Enum — CyberShield Arena Phase 1
 *
 * OOP Concept: Enum (Enumeration)
 * Purpose   : Represents the operational state of any network device.
 *             Using an enum instead of raw strings or ints prevents
 *             invalid states such as "Onlne" typos or magic numbers.
 *
 * Values:
 *   ONLINE  — device is active and reachable on the virtual network.
 *   OFFLINE — device is inactive or has been deactivated.
 */
public enum DeviceStatus {

    ONLINE("Online"),
    OFFLINE("Offline");

    // ---------------------------------------------------------------
    // Each constant carries a human-readable display label.
    // ---------------------------------------------------------------
    private final String displayLabel;

    /**
     * Private enum constructor — called once per constant at class load.
     *
     * @param displayLabel  the label printed in the console output
     */
    DeviceStatus(String displayLabel) {
        this.displayLabel = displayLabel;
    }

    /**
     * Returns the friendly display label for use in console output.
     *
     * @return "Online" or "Offline"
     */
    public String getDisplayLabel() {
        return displayLabel;
    }

    /**
     * Overrides the default toString so that printing a DeviceStatus
     * value directly gives the display label, not the constant name.
     *
     * @return display label string
     */
    @Override
    public String toString() {
        return displayLabel;
    }
}
