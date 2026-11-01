package cybershield.model;

/**
 * Workstation — Concrete Subclass of NetworkNode — CyberShield Arena Phase 1
 *
 * OOP Concepts demonstrated:
 *   - Inheritance      : extends NetworkNode → reuses all parent logic.
 *   - Method Overriding: provides its own displayDetails() implementation.
 *   - Encapsulation    : own fields are private with validated setters.
 *   - Constructors     : calls super() to delegate common setup.
 *
 * A Workstation models an end-user machine on the virtual network,
 * identified by its operating system and the currently logged-in user.
 */
public class Workstation extends NetworkNode {

    // ---------------------------------------------------------------
    // Workstation-specific private fields
    // ---------------------------------------------------------------

    /** Operating system installed on the workstation, e.g. "Windows 11". */
    private String operatingSystem;

    /** Username of the currently logged-in user, e.g. "student". */
    private String loggedInUser;

    // ---------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------

    /**
     * Creates a new Workstation with all required fields.
     *
     * @param nodeId          unique ID,          e.g. "WS-001"
     * @param nodeName        display name,       e.g. "Student Workstation"
     * @param ipAddress       IPv4 address,       e.g. "192.168.1.20"
     * @param operatingSystem OS name,            e.g. "Windows 11"
     * @param loggedInUser    current username,   e.g. "student"
     * @throws IllegalArgumentException if any validation fails
     */
    public Workstation(String nodeId, String nodeName, String ipAddress,
                       String operatingSystem, String loggedInUser) {
        // Delegate common field setup (with validation) to the parent.
        super(nodeId, nodeName, ipAddress);

        // Initialise Workstation-specific fields.
        setOperatingSystem(operatingSystem);
        setLoggedInUser(loggedInUser);
    }

    // ---------------------------------------------------------------
    // displayDetails() — Method Overriding
    // ---------------------------------------------------------------

    /**
     * Prints a formatted block of all Workstation details to the console.
     *
     * OOP Concept: @Override — Workstation-specific display.
     *              Called polymorphically through a NetworkNode reference.
     */
    @Override
    public void displayDetails() {
        System.out.println("  ┌─────────────────────────────────────┐");
        System.out.println("  │           [WORKSTATION]             │");
        System.out.println("  └─────────────────────────────────────┘");
        System.out.println("  ID              : " + getNodeId());
        System.out.println("  Name            : " + getNodeName());
        System.out.println("  IP Address      : " + getIpAddress());
        System.out.println("  Status          : " + getStatus());
        System.out.println("  Operating System: " + operatingSystem);
        System.out.println("  Logged-in User  : " + loggedInUser);
        System.out.println();
    }

    // ---------------------------------------------------------------
    // Getters
    // ---------------------------------------------------------------

    /** @return the installed operating system name */
    public String getOperatingSystem() { return operatingSystem; }

    /** @return the username of the currently logged-in user */
    public String getLoggedInUser() { return loggedInUser; }

    // ---------------------------------------------------------------
    // Setters with validation
    // ---------------------------------------------------------------

    /**
     * Sets the operating system name after validating it is not blank.
     *
     * @param operatingSystem non-blank OS name
     * @throws IllegalArgumentException if blank
     */
    public final void setOperatingSystem(String operatingSystem) {
        if (operatingSystem == null || operatingSystem.trim().isEmpty()) {
            throw new IllegalArgumentException("Operating system must not be blank.");
        }
        this.operatingSystem = operatingSystem.trim();
    }

    /**
     * Sets the logged-in username after validating it is not blank.
     *
     * @param loggedInUser non-blank username string
     * @throws IllegalArgumentException if blank
     */
    public final void setLoggedInUser(String loggedInUser) {
        if (loggedInUser == null || loggedInUser.trim().isEmpty()) {
            throw new IllegalArgumentException("Logged-in user must not be blank.");
        }
        this.loggedInUser = loggedInUser.trim();
    }
}
