package cybershield.model;

/**
 * Router — Concrete Subclass of NetworkNode — CyberShield Arena Phase 1
 *
 * OOP Concepts demonstrated:
 *   - Inheritance      : extends NetworkNode → reuses all parent logic.
 *   - Method Overriding: provides its own displayDetails() implementation.
 *   - Encapsulation    : own fields are private with dedicated toggle methods.
 *   - Constructors     : calls super() to delegate common setup.
 *
 * A Router controls packet forwarding between network segments.
 * Routing can be enabled or disabled independently of the device status.
 */
public class Router extends NetworkNode {

    // ---------------------------------------------------------------
    // Router-specific private field
    // ---------------------------------------------------------------

    /**
     * Indicates whether this router actively forwards network packets.
     * Defaults to false (disabled) until explicitly enabled.
     */
    private boolean routingEnabled;

    // ---------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------

    /**
     * Creates a new Router with all required fields.
     *
     * @param nodeId         unique ID,        e.g. "RTR-001"
     * @param nodeName       display name,     e.g. "Main Router"
     * @param ipAddress      IPv4 address,     e.g. "192.168.1.1"
     * @param routingEnabled initial routing state (true = enabled)
     * @throws IllegalArgumentException if base-class validation fails
     */
    public Router(String nodeId, String nodeName, String ipAddress,
                  boolean routingEnabled) {
        // Delegate common field setup to the parent constructor.
        super(nodeId, nodeName, ipAddress);
        this.routingEnabled = routingEnabled;
    }

    // ---------------------------------------------------------------
    // displayDetails() — Method Overriding
    // ---------------------------------------------------------------

    /**
     * Prints a formatted block of all Router details to the console.
     *
     * OOP Concept: @Override — Router-specific display format.
     *              Invoked polymorphically through a NetworkNode reference.
     */
    @Override
    public void displayDetails() {
        System.out.println("  ┌─────────────────────────────────────┐");
        System.out.println("  │              [ROUTER]               │");
        System.out.println("  └─────────────────────────────────────┘");
        System.out.println("  ID              : " + getNodeId());
        System.out.println("  Name            : " + getNodeName());
        System.out.println("  IP Address      : " + getIpAddress());
        System.out.println("  Status          : " + getStatus());
        System.out.println("  Routing Enabled : " + (routingEnabled ? "Yes" : "No"));
        System.out.println();
    }

    // ---------------------------------------------------------------
    // Routing Toggle Methods
    // ---------------------------------------------------------------

    /**
     * Enables packet routing on this router.
     * Prints a confirmation message so the operator can see the change.
     */
    public void enableRouting() {
        this.routingEnabled = true;
        System.out.println("[ROUTER] Routing ENABLED on " + getNodeName()
                + " (" + getNodeId() + ").");
    }

    /**
     * Disables packet routing on this router.
     * Prints a confirmation message so the operator can see the change.
     */
    public void disableRouting() {
        this.routingEnabled = false;
        System.out.println("[ROUTER] Routing DISABLED on " + getNodeName()
                + " (" + getNodeId() + ").");
    }

    // ---------------------------------------------------------------
    // Getter
    // ---------------------------------------------------------------

    /** @return true if routing is currently enabled, false otherwise */
    public boolean isRoutingEnabled() { return routingEnabled; }
}
