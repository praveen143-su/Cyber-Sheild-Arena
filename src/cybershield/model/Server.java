package cybershield.model;

/**
 * Server — Concrete Subclass of NetworkNode — CyberShield Arena Phase 1
 *
 * OOP Concepts demonstrated:
 *   - Inheritance      : extends NetworkNode → inherits all fields and methods.
 *   - Method Overriding: provides its own implementation of displayDetails().
 *   - Encapsulation    : own fields are private with validated setters.
 *   - Constructors     : calls super() to initialise inherited fields.
 *   - Validation       : port number must be in range 1–65535.
 *
 * A Server represents a machine in the virtual network that exposes
 * a named service (e.g. HTTP, FTP, SSH) on a specific TCP/UDP port.
 */
public class Server extends NetworkNode {

    // ---------------------------------------------------------------
    // Server-specific private fields
    // ---------------------------------------------------------------

    /** Name of the service running on this server, e.g. "HTTP", "SSH". */
    private String serviceName;

    /**
     * TCP/UDP port the service listens on.
     * Valid range: 1 – 65535.
     */
    private int portNumber;

    // ---------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------

    /**
     * Creates a new Server with all required fields.
     *
     * OOP Concept: super() delegates common field initialisation
     *              (with validation) to the parent constructor.
     *
     * @param nodeId      unique ID,        e.g. "SRV-001"
     * @param nodeName    display name,     e.g. "Application Server"
     * @param ipAddress   IPv4 address,     e.g. "192.168.1.10"
     * @param serviceName service name,     e.g. "HTTP"
     * @param portNumber  port 1–65535,     e.g. 8080
     * @throws IllegalArgumentException if any validation fails
     */
    public Server(String nodeId, String nodeName, String ipAddress,
                  String serviceName, int portNumber) {
        // Step 1: Initialise inherited fields through the parent constructor.
        super(nodeId, nodeName, ipAddress);

        // Step 2: Initialise Server-specific fields with their own validation.
        setServiceName(serviceName);
        setPortNumber(portNumber);
    }

    // ---------------------------------------------------------------
    // displayDetails() — Method Overriding
    // ---------------------------------------------------------------

    /**
     * Prints a formatted block of all Server details to the console.
     *
     * OOP Concept: @Override — replaces the abstract method in NetworkNode
     *              with a Server-specific implementation. When called through
     *              a NetworkNode reference, Java resolves this method at
     *              runtime (dynamic dispatch / polymorphism).
     */
    @Override
    public void displayDetails() {
        System.out.println("  ┌─────────────────────────────────────┐");
        System.out.println("  │              [SERVER]               │");
        System.out.println("  └─────────────────────────────────────┘");
        System.out.println("  ID          : " + getNodeId());
        System.out.println("  Name        : " + getNodeName());
        System.out.println("  IP Address  : " + getIpAddress());
        System.out.println("  Status      : " + getStatus());
        System.out.println("  Service     : " + serviceName);
        System.out.println("  Port        : " + portNumber);
        System.out.println();
    }

    // ---------------------------------------------------------------
    // Getters
    // ---------------------------------------------------------------

    /** @return the service name running on this server */
    public String getServiceName() { return serviceName; }

    /** @return the port number the service listens on */
    public int getPortNumber() { return portNumber; }

    // ---------------------------------------------------------------
    // Setters with validation
    // ---------------------------------------------------------------

    /**
     * Sets the service name after validating it is not blank.
     *
     * @param serviceName non-blank service label
     * @throws IllegalArgumentException if blank
     */
    public final void setServiceName(String serviceName) {
        if (serviceName == null || serviceName.trim().isEmpty()) {
            throw new IllegalArgumentException("Service name must not be blank.");
        }
        this.serviceName = serviceName.trim();
    }

    /**
     * Sets the port number after validating it is within 1–65535.
     *
     * @param portNumber integer in range 1–65535
     * @throws IllegalArgumentException if out of range
     */
    public final void setPortNumber(int portNumber) {
        if (portNumber < 1 || portNumber > 65535) {
            throw new IllegalArgumentException(
                "Port number " + portNumber + " is invalid. Must be between 1 and 65535."
            );
        }
        this.portNumber = portNumber;
    }
}
