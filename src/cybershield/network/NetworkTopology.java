package cybershield.network;

import cybershield.model.DeviceStatus;
import cybershield.model.NetworkNode;
import cybershield.security.FirewallAction;
import cybershield.security.FirewallRule;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * NetworkTopology — CyberShield Arena Phase 2
 *
 * OOP Concepts demonstrated:
 *   - Composition        : Owns and manages a collection of NetworkConnection objects.
 *   - Loose Coupling     : Interacts with VirtualNetwork via defined interfaces.
 *   - Strategy / Policy  : Applies prioritized FirewallRule policies (First Match Wins).
 *   - Event Handling     : Subscribes to device removal events for cascading cleanup.
 *   - Defensive Design   : Validates device readiness, prevents duplicates & self-loops.
 *
 * Coordinates the virtual network's structure, enforcing firewall security rules
 * and tracking live/blocked/disconnected connections between nodes.
 */
public class NetworkTopology {

    private final VirtualNetwork network;

    /** Map of Connection ID -> NetworkConnection instance. */
    private final Map<String, NetworkConnection> connections = new LinkedHashMap<>();

    /** Ordered list of firewall rules (First match wins). */
    private final List<FirewallRule> firewallRules = new ArrayList<>();

    /** Auto-incrementing counter for unique connection IDs. */
    private int connectionSequence = 1;

    /**
     * Constructs a NetworkTopology tied to the given VirtualNetwork.
     * Automatically registers a listener to clean up connections when a device is removed.
     *
     * @param network authoritative VirtualNetwork registry
     * @throws IllegalArgumentException if network is null
     */
    public NetworkTopology(VirtualNetwork network) {
        if (network == null) {
            throw new IllegalArgumentException("VirtualNetwork reference cannot be null.");
        }
        this.network = network;

        // Auto-subscribe to device removal to guarantee topology integrity
        this.network.onDeviceRemoved(this::removeConnectionsForDevice);
    }

    // ---------------------------------------------------------------
    // Firewall Management & Evaluation
    // ---------------------------------------------------------------

    /**
     * Adds a firewall rule to the topology.
     * Rules are evaluated in insertion order.
     *
     * @param rule the FirewallRule to add
     * @throws IllegalArgumentException if rule is null
     */
    public void addFirewallRule(FirewallRule rule) {
        if (rule == null) {
            throw new IllegalArgumentException("Firewall rule cannot be null.");
        }
        firewallRules.add(rule);
        System.out.println("[Firewall] Added Rule: " + rule);
    }

    /**
     * Inserts a high-priority firewall rule at index 0 (top of the rule list).
     * Since the firewall operates on a 'first-match-wins' basis, rules added here take precedence.
     *
     * @param rule the FirewallRule to prepend
     */
    public void addFirewallRuleFirst(FirewallRule rule) {
        if (rule == null) {
            throw new IllegalArgumentException("Firewall rule cannot be null.");
        }
        firewallRules.add(0, rule);
        System.out.println("[Firewall] Added Priority Rule (Index 0): " + rule);
    }

    /**
     * Removes a firewall rule by its unique Rule ID.
     *
     * @param ruleId ID of rule to remove
     * @return true if removed, false if not found
     */
    public boolean removeFirewallRule(String ruleId) {
        if (ruleId == null) return false;
        boolean removed = firewallRules.removeIf(r -> r.getRuleId().equalsIgnoreCase(ruleId.trim()));
        if (removed) {
            System.out.println("[Firewall] Removed Rule: " + ruleId);
        }
        return removed;
    }

    /**
     * Evaluates all firewall rules for traffic from source to target.
     * Policy:
     *   1. First matching rule wins.
     *   2. Default policy = BLOCK (safe default / zero-trust principle).
     *
     * @param sourceNodeId source device node ID
     * @param targetNodeId target device node ID
     * @return FirewallAction.ALLOW if an explicit ALLOW rule matched first;
     *         otherwise FirewallAction.BLOCK
     */
    public FirewallAction evaluateFirewall(String sourceNodeId, String targetNodeId) {
        for (FirewallRule rule : firewallRules) {
            if (rule.matches(sourceNodeId, targetNodeId)) {
                System.out.printf("[Firewall] Match found: %s triggered action %s for %s -> %s\n",
                        rule.getRuleId(), rule.getAction(), sourceNodeId, targetNodeId);
                return rule.getAction();
            }
        }

        System.out.printf("[Firewall] No matching rule found for %s -> %s. Applying DEFAULT policy: BLOCK\n",
                sourceNodeId, targetNodeId);
        return FirewallAction.BLOCK; // Safe default
    }

    /**
     * Returns an unmodifiable list of active firewall rules.
     *
     * @return unmodifiable List of FirewallRule
     */
    public List<FirewallRule> getFirewallRules() {
        return Collections.unmodifiableList(new ArrayList<>(firewallRules));
    }

    // ---------------------------------------------------------------
    // Connection Lifecycle Management
    // ---------------------------------------------------------------

    /**
     * Creates a connection between two registered devices subject to:
     *   1. Valid device registration
     *   2. No self-connections (source != target)
     *   3. Both devices must be ONLINE (DeviceStatus.ONLINE)
     *   4. No duplicate active/blocked connection (source -> target)
     *   5. Firewall policy evaluation (ALLOW -> ACTIVE, BLOCK -> BLOCKED)
     *
     * @param sourceNodeId source device ID
     * @param targetNodeId target device ID
     * @return the created NetworkConnection object
     * @throws IllegalArgumentException if devices do not exist or self-connection attempted
     * @throws IllegalStateException    if a device is OFFLINE or duplicate connection exists
     */
    public NetworkConnection createConnection(String sourceNodeId, String targetNodeId) {
        if (sourceNodeId == null || sourceNodeId.trim().isEmpty()) {
            throw new IllegalArgumentException("Source Node ID cannot be blank.");
        }
        if (targetNodeId == null || targetNodeId.trim().isEmpty()) {
            throw new IllegalArgumentException("Target Node ID cannot be blank.");
        }

        String src = sourceNodeId.trim();
        String tgt = targetNodeId.trim();

        // 1. Check self-connection
        if (src.equalsIgnoreCase(tgt)) {
            throw new IllegalArgumentException("Self-connection rejected: source and target device are the same (" + src + ").");
        }

        // 2. Validate device registration in VirtualNetwork
        NetworkNode sourceNode = network.findDeviceById(src).orElseThrow(() ->
                new IllegalArgumentException("Connection failed: Source device '" + src + "' is not registered in the virtual network."));

        NetworkNode targetNode = network.findDeviceById(tgt).orElseThrow(() ->
                new IllegalArgumentException("Connection failed: Target device '" + tgt + "' is not registered in the virtual network."));

        // 3. Validate device status (must be ONLINE and NOT ISOLATED)
        if (sourceNode.getStatus() != DeviceStatus.ONLINE) {
            throw new IllegalStateException("Connection rejected: Source device '" +
                    sourceNode.getNodeName() + " (" + src + ")' is OFFLINE.");
        }
        if (targetNode.getStatus() != DeviceStatus.ONLINE) {
            throw new IllegalStateException("Connection rejected: Target device '" +
                    targetNode.getNodeName() + " (" + tgt + ")' is OFFLINE.");
        }
        if (sourceNode.isIsolated()) {
            throw new IllegalStateException("Connection rejected: Source device '" +
                    sourceNode.getNodeName() + " (" + src + ")' is ISOLATED by defensive quarantine.");
        }
        if (targetNode.isIsolated()) {
            throw new IllegalStateException("Connection rejected: Target device '" +
                    targetNode.getNodeName() + " (" + tgt + ")' is ISOLATED by defensive quarantine.");
        }

        // 4. Prevent duplicate active/blocked connections
        for (NetworkConnection conn : connections.values()) {
            if (conn.getSourceNodeId().equalsIgnoreCase(src) &&
                conn.getTargetNodeId().equalsIgnoreCase(tgt) &&
                conn.getConnectionStatus() != ConnectionStatus.DISCONNECTED) {
                throw new IllegalStateException("Duplicate connection rejected: An active or blocked connection already exists from " +
                        src + " to " + tgt + " (ID: " + conn.getConnectionId() + ").");
            }
        }

        // 5. Evaluate Firewall Rules
        FirewallAction action = evaluateFirewall(src, tgt);
        ConnectionStatus status = (action == FirewallAction.ALLOW) ? ConnectionStatus.ACTIVE : ConnectionStatus.BLOCKED;

        String connectionId = String.format("CONN-%03d", connectionSequence++);
        NetworkConnection connection = new NetworkConnection(connectionId, src, tgt, status);
        connections.put(connectionId, connection);

        if (status == ConnectionStatus.ACTIVE) {
            System.out.printf("[Topology] Connection ESTABLISHED: %s (%s -> %s) [Status: ACTIVE]\n",
                    connectionId, src, tgt);
        } else {
            System.out.printf("[Topology] Connection INTERCEPTED: %s (%s -> %s) [Status: BLOCKED by Firewall]\n",
                    connectionId, src, tgt);
        }

        return connection;
    }

    /**
     * Disconnects an existing connection by its connection ID.
     *
     * @param connectionId ID of the connection to terminate
     * @return true if found and disconnected
     */
    public boolean disconnectConnection(String connectionId) {
        if (connectionId == null) return false;
        NetworkConnection conn = connections.get(connectionId.trim());
        if (conn != null) {
            conn.disconnect();
            System.out.println("[Topology] Connection " + connectionId + " has been DISCONNECTED.");
            return true;
        }
        return false;
    }

    /**
     * Manually blocks an active connection.
     *
     * @param connectionId ID of connection to block
     * @return true if successfully blocked
     */
    public boolean blockConnection(String connectionId) {
        if (connectionId == null) return false;
        NetworkConnection conn = connections.get(connectionId.trim());
        if (conn != null) {
            conn.block();
            System.out.println("[Topology] Connection " + connectionId + " has been BLOCKED.");
            return true;
        }
        return false;
    }

    /**
     * Unblocks a blocked connection, restoring it to ACTIVE status.
     *
     * @param connectionId ID of connection to unblock
     * @return true if successfully restored
     */
    public boolean unblockConnection(String connectionId) {
        if (connectionId == null) return false;
        NetworkConnection conn = connections.get(connectionId.trim());
        if (conn != null) {
            conn.activate();
            System.out.println("[Topology] Connection " + connectionId + " has been UNBLOCKED and is now ACTIVE.");
            return true;
        }
        return false;
    }

    /**
     * Removes all connections (inbound and outbound) associated with a given node.
     * Ensures topology consistency when devices leave the network.
     *
     * @param nodeId node identifier
     * @return total count of connections purged
     */
    public int removeConnectionsForDevice(String nodeId) {
        if (nodeId == null) return 0;
        String target = nodeId.trim();

        List<String> toRemove = new ArrayList<>();
        for (NetworkConnection conn : connections.values()) {
            if (conn.connectsNode(target)) {
                toRemove.add(conn.getConnectionId());
            }
        }

        for (String connId : toRemove) {
            connections.remove(connId);
        }

        if (!toRemove.isEmpty()) {
            System.out.printf("[Topology] Cleaned up %d connection(s) associated with removed device '%s'.\n",
                    toRemove.size(), target);
        }
        return toRemove.size();
    }

    // ---------------------------------------------------------------
    // Query Methods
    // ---------------------------------------------------------------

    public Optional<NetworkConnection> findConnection(String connectionId) {
        if (connectionId == null) return Optional.empty();
        return Optional.ofNullable(connections.get(connectionId.trim()));
    }

    /**
     * Finds all connections where the specified node is source or target.
     *
     * @param nodeId node ID to look up
     * @return List of matching connections
     */
    public List<NetworkConnection> getConnectionsForDevice(String nodeId) {
        if (nodeId == null) return Collections.emptyList();
        String id = nodeId.trim();
        List<NetworkConnection> result = new ArrayList<>();
        for (NetworkConnection conn : connections.values()) {
            if (conn.connectsNode(id)) {
                result.add(conn);
            }
        }
        return Collections.unmodifiableList(result);
    }

    /**
     * Returns an unmodifiable view of all connections.
     *
     * @return unmodifiable List of NetworkConnection
     */
    public List<NetworkConnection> getAllConnections() {
        return Collections.unmodifiableList(new ArrayList<>(connections.values()));
    }

    public int getTotalConnectionCount() {
        return connections.size();
    }

    public int getActiveConnectionCount() {
        int count = 0;
        for (NetworkConnection conn : connections.values()) {
            if (conn.isActive()) count++;
        }
        return count;
    }

    public int getBlockedConnectionCount() {
        int count = 0;
        for (NetworkConnection conn : connections.values()) {
            if (conn.isBlocked()) count++;
        }
        return count;
    }

    public int getDisconnectedConnectionCount() {
        int count = 0;
        for (NetworkConnection conn : connections.values()) {
            if (conn.isDisconnected()) count++;
        }
        return count;
    }

    // ---------------------------------------------------------------
    // Display & Visualization
    // ---------------------------------------------------------------

    /**
     * Displays a clean console view of all configured firewall rules.
     */
    public void displayFirewallRules() {
        System.out.println("\n+------------------------------------------------------------------------------------+");
        System.out.printf("| %-82s |\n", "ACTIVE FIREWALL POLICIES (" + firewallRules.size() + " Rules — Default: BLOCK)");
        System.out.println("+------------+----------------------+----------------------+-------------------------+");
        System.out.printf("| %-10s | %-20s | %-20s | %-23s |\n",
                "Rule ID", "Source Node", "Target Node", "Action");
        System.out.println("+------------+----------------------+----------------------+-------------------------+");

        for (FirewallRule rule : firewallRules) {
            System.out.printf("| %-10s | %-20s | %-20s | %-23s |\n",
                    rule.getRuleId(),
                    rule.getSourceNodeId(),
                    rule.getTargetNodeId(),
                    rule.getAction());
        }

        System.out.println("+------------+----------------------+----------------------+-------------------------+");
        System.out.println("  * Policy Evaluation: First matching rule wins. Default fallback = BLOCK (Deny All).\n");
    }

    /**
     * Displays a formatted topology table showing all simulated connections.
     */
    public void displayTopology() {
        System.out.println("\n+------------------------------------------------------------------------------------+");
        System.out.printf("| %-82s |\n", "NETWORK TOPOLOGY (" + getTotalConnectionCount() + " Connections)");
        System.out.println("+------------+--------------------+--------------------+---------------+-----------------+");
        System.out.printf("| %-10s | %-18s | %-18s | %-13s | %-15s |\n",
                "Conn ID", "Source Node", "Target Node", "Status", "Link Type");
        System.out.println("+------------+--------------------+--------------------+---------------+-----------------+");

        for (NetworkConnection conn : connections.values()) {
            String srcName = network.findDeviceById(conn.getSourceNodeId())
                    .map(NetworkNode::getNodeName).orElse("Unknown");
            String tgtName = network.findDeviceById(conn.getTargetNodeId())
                    .map(NetworkNode::getNodeName).orElse("Unknown");

            System.out.printf("| %-10s | %-18s | %-18s | %-13s | %-15s |\n",
                    conn.getConnectionId(),
                    conn.getSourceNodeId() + " (" + srcName + ")",
                    conn.getTargetNodeId() + " (" + tgtName + ")",
                    conn.getConnectionStatus(),
                    "Simulated");
        }

        System.out.println("+------------+--------------------+--------------------+---------------+-----------------+");
        System.out.printf("  Topology Summary: Total=%d | Active=%d | Blocked=%d | Disconnected=%d\n\n",
                getTotalConnectionCount(),
                getActiveConnectionCount(),
                getBlockedConnectionCount(),
                getDisconnectedConnectionCount());
    }
}
