package cybershield.model;

/**
 * NetworkNode — Abstract Base Class — CyberShield Arena Phase 1
 *
 * OOP Concepts demonstrated:
 *   - Abstract Class   : Cannot be instantiated directly; acts as a blueprint.
 *   - Encapsulation    : All fields are private; accessed via getters/setters.
 *   - Abstraction      : displayDetails() is declared abstract — every
 *                        subclass MUST provide its own implementation.
 *   - Constructors     : Parameterised constructor with input validation.
 *
 * This class defines the common identity and behaviour shared by every
 * device (Server, Workstation, Router) in the virtual CyberShield network.
 */
public abstract class NetworkNode {

    // ---------------------------------------------------------------
    // Private fields — Encapsulation: only this class can touch them.
    // ---------------------------------------------------------------

    /** Unique identifier for the node, e.g. "SRV-001". */
    private String nodeId;

    /** Human-readable name of the device. */
    private String nodeName;

    /** IPv4 address in dotted-decimal format, e.g. "192.168.1.10". */
    private String ipAddress;

    /** Operational status of the device. Defaults to OFFLINE at creation. */
    private DeviceStatus status;

    /**
     * Phase 6: Simulated quarantine/isolation status.
     * Preserves operational status (ONLINE/OFFLINE) separately from isolation state.
     */
    private boolean isolated = false;

    // ---------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------

    /**
     * Initialises a new NetworkNode with validated inputs.
     *
     * @param nodeId    unique identifier (must not be blank)
     * @param nodeName  display name (must not be blank)
     * @param ipAddress valid IPv4 address string
     * @throws IllegalArgumentException if any argument fails validation
     */
    public NetworkNode(String nodeId, String nodeName, String ipAddress) {
        setNodeId(nodeId);
        setNodeName(nodeName);
        setIpAddress(ipAddress);
        this.status = DeviceStatus.OFFLINE; // safe default
    }

    // ---------------------------------------------------------------
    // Abstract Method — forces every subclass to implement it.
    // ---------------------------------------------------------------

    /**
     * Displays the full details of this network device.
     * Each subclass renders its own specific format.
     *
     * OOP Concept: Abstraction + Method Overriding
     */
    public abstract void displayDetails();

    // ---------------------------------------------------------------
    // Common Behaviour — shared by ALL subclasses
    // ---------------------------------------------------------------

    /**
     * Activates the device by setting its status to ONLINE.
     * OOP Concept: Common method defined once in the parent class
     *              and inherited by all children.
     */
    public void activate() {
        this.status = DeviceStatus.ONLINE;
        System.out.println("[SYSTEM] " + nodeName + " (" + nodeId + ") is now ONLINE.");
    }

    /**
     * Deactivates the device by setting its status to OFFLINE.
     */
    public void deactivate() {
        this.status = DeviceStatus.OFFLINE;
        System.out.println("[SYSTEM] " + nodeName + " (" + nodeId + ") is now OFFLINE.");
    }

    // ---------------------------------------------------------------
    // Getters — read-only access to private fields
    // ---------------------------------------------------------------

    /** @return the unique node identifier */
    public String getNodeId() { return nodeId; }

    /** @return the human-readable device name */
    public String getNodeName() { return nodeName; }

    /** @return the IPv4 address string */
    public String getIpAddress() { return ipAddress; }

    /** @return the current DeviceStatus (ONLINE or OFFLINE) */
    public DeviceStatus getStatus() { return status; }

    /**
     * Checks if this device is currently isolated (quarantined) by the automated defense system.
     *
     * @return true if isolated, false otherwise
     */
    public boolean isIsolated() { return isolated; }

    /**
     * Sets the simulated isolation state of this device.
     *
     * @param isolated true to isolate/quarantine, false to restore
     */
    public void setIsolated(boolean isolated) { this.isolated = isolated; }

    // ---------------------------------------------------------------
    // Setters with validation
    // ---------------------------------------------------------------

    /**
     * Sets the node ID after validating it is not blank.
     *
     * @param nodeId non-blank identifier string
     * @throws IllegalArgumentException if blank
     */
    public final void setNodeId(String nodeId) {
        if (nodeId == null || nodeId.trim().isEmpty()) {
            throw new IllegalArgumentException("Node ID must not be blank.");
        }
        this.nodeId = nodeId.trim();
    }

    /**
     * Sets the node name after validating it is not blank.
     *
     * @param nodeName non-blank name string
     * @throws IllegalArgumentException if blank
     */
    public final void setNodeName(String nodeName) {
        if (nodeName == null || nodeName.trim().isEmpty()) {
            throw new IllegalArgumentException("Node name must not be blank.");
        }
        this.nodeName = nodeName.trim();
    }

    /**
     * Sets the IP address after validating it matches IPv4 format.
     * Accepts addresses from 0.0.0.0 to 255.255.255.255.
     *
     * @param ipAddress dotted-decimal IPv4 string
     * @throws IllegalArgumentException if format is invalid
     */
    public final void setIpAddress(String ipAddress) {
        if (!isValidIpAddress(ipAddress)) {
            throw new IllegalArgumentException(
                "Invalid IP address: \"" + ipAddress + "\". " +
                "Expected format: 0-255.0-255.0-255.0-255"
            );
        }
        this.ipAddress = ipAddress.trim();
    }

    // ---------------------------------------------------------------
    // Private helper — IP validation
    // ---------------------------------------------------------------

    /**
     * Validates an IPv4 address using a regex pattern.
     * Each octet must be 0–255.
     *
     * @param ip the string to validate
     * @return true if valid IPv4 format, false otherwise
     */
    private boolean isValidIpAddress(String ip) {
        if (ip == null || ip.trim().isEmpty()) return false;

        // Regex: exactly 4 groups of 1-3 digits separated by dots
        String ipv4Pattern =
            "^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}" +
            "(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$";

        return ip.trim().matches(ipv4Pattern);
    }

    // ---------------------------------------------------------------
    // toString — useful for debugging
    // ---------------------------------------------------------------

    /**
     * Returns a compact summary string for logging/debugging.
     */
    @Override
    public String toString() {
        return String.format("NetworkNode[id=%s, name=%s, ip=%s, status=%s]",
                nodeId, nodeName, ipAddress, status);
    }
}
