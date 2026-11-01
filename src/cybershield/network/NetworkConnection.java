package cybershield.network;

import java.util.Objects;

/**
 * NetworkConnection — CyberShield Arena Phase 2
 *
 * OOP Concepts demonstrated:
 *   - Encapsulation : Private fields with validated accessors and controlled state transitions.
 *   - State Pattern : Controlled methods (activate, block, disconnect) that enforce valid states.
 *   - Defensive Programming : Guard clauses against null, blank identifiers, and self-connections.
 *
 * Represents a simulated directional connection between two network devices (sourceNodeId -> targetNodeId).
 */
public class NetworkConnection {

    private final String connectionId;
    private final String sourceNodeId;
    private final String targetNodeId;
    private ConnectionStatus connectionStatus;

    /**
     * Constructs a NetworkConnection with an initial status of ACTIVE.
     *
     * @param connectionId unique connection identifier (e.g. "CONN-001")
     * @param sourceNodeId source device node ID
     * @param targetNodeId target device node ID
     * @throws IllegalArgumentException if any field is invalid or if sourceNodeId equals targetNodeId
     */
    public NetworkConnection(String connectionId, String sourceNodeId, String targetNodeId) {
        this(connectionId, sourceNodeId, targetNodeId, ConnectionStatus.ACTIVE);
    }

    /**
     * Constructs a NetworkConnection with a specific initial status.
     *
     * @param connectionId     unique connection identifier
     * @param sourceNodeId     source device node ID
     * @param targetNodeId     target device node ID
     * @param connectionStatus initial state of connection
     * @throws IllegalArgumentException if arguments are invalid or source equals target
     */
    public NetworkConnection(String connectionId, String sourceNodeId, String targetNodeId, ConnectionStatus connectionStatus) {
        if (connectionId == null || connectionId.trim().isEmpty()) {
            throw new IllegalArgumentException("Connection ID must not be null or blank.");
        }
        if (sourceNodeId == null || sourceNodeId.trim().isEmpty()) {
            throw new IllegalArgumentException("Source Node ID must not be null or blank.");
        }
        if (targetNodeId == null || targetNodeId.trim().isEmpty()) {
            throw new IllegalArgumentException("Target Node ID must not be null or blank.");
        }
        if (sourceNodeId.trim().equalsIgnoreCase(targetNodeId.trim())) {
            throw new IllegalArgumentException(
                "Self-connection rejected: source (" + sourceNodeId.trim() +
                ") and target cannot be the same device."
            );
        }
        if (connectionStatus == null) {
            throw new IllegalArgumentException("Connection status cannot be null.");
        }

        this.connectionId = connectionId.trim();
        this.sourceNodeId = sourceNodeId.trim();
        this.targetNodeId = targetNodeId.trim();
        this.connectionStatus = connectionStatus;
    }

    // ---------------------------------------------------------------
    // Controlled State Transition Methods
    // ---------------------------------------------------------------

    /**
     * Transitions this connection to ACTIVE state.
     */
    public void activate() {
        this.connectionStatus = ConnectionStatus.ACTIVE;
    }

    /**
     * Transitions this connection to BLOCKED state.
     */
    public void block() {
        this.connectionStatus = ConnectionStatus.BLOCKED;
    }

    /**
     * Transitions this connection to DISCONNECTED state.
     */
    public void disconnect() {
        this.connectionStatus = ConnectionStatus.DISCONNECTED;
    }

    // ---------------------------------------------------------------
    // Query & Helper Methods
    // ---------------------------------------------------------------

    public boolean isActive() {
        return connectionStatus == ConnectionStatus.ACTIVE;
    }

    public boolean isBlocked() {
        return connectionStatus == ConnectionStatus.BLOCKED;
    }

    public boolean isDisconnected() {
        return connectionStatus == ConnectionStatus.DISCONNECTED;
    }

    /**
     * Checks if this connection involves the specified node ID as either source or target.
     *
     * @param nodeId node identifier to check
     * @return true if this connection connects the given node
     */
    public boolean connectsNode(String nodeId) {
        if (nodeId == null) return false;
        String trimmed = nodeId.trim();
        return sourceNodeId.equalsIgnoreCase(trimmed) || targetNodeId.equalsIgnoreCase(trimmed);
    }

    // ---------------------------------------------------------------
    // Getters
    // ---------------------------------------------------------------

    public String getConnectionId() {
        return connectionId;
    }

    public String getSourceNodeId() {
        return sourceNodeId;
    }

    public String getTargetNodeId() {
        return targetNodeId;
    }

    public ConnectionStatus getConnectionStatus() {
        return connectionStatus;
    }

    // ---------------------------------------------------------------
    // Object Overrides
    // ---------------------------------------------------------------

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NetworkConnection that = (NetworkConnection) o;
        return Objects.equals(connectionId, that.connectionId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(connectionId);
    }

    @Override
    public String toString() {
        return String.format("[%s] %s -> %s (%s)",
                connectionId, sourceNodeId, targetNodeId, connectionStatus);
    }
}
