package cybershield.defense;

import cybershield.model.NetworkNode;
import cybershield.network.NetworkConnection;
import cybershield.network.NetworkTopology;
import cybershield.network.VirtualNetwork;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * DefenseContext — CyberShield Arena Phase 6
 *
 * OOP Concepts demonstrated:
 *   - Encapsulation & Controlled Access: Wraps access to the virtual network and topology.
 *   - Security Boundary: Ensures defensive strategies interact ONLY with virtual simulation models.
 *                        Strictly prohibits any real OS or system-level network operations.
 *   - State Coordination: Manages temporary block metadata, simulation ticks, and expiration tracking.
 */
public class DefenseContext {

    private final VirtualNetwork network;
    private final NetworkTopology topology;

    /**
     * Tracks active temporary blocks (Rule/Connection ID -> Expiration Tick or Timestamp).
     * Thread-safe map for simulated temporary blocks.
     */
    private final Map<String, TemporaryBlockRecord> activeTemporaryBlocks = new ConcurrentHashMap<>();

    /**
     * Simulated virtual clock counter for reproducible and deterministic time progression.
     */
    private int simulationTick = 0;

    /**
     * Record holding metadata about a temporary block.
     */
    public static class TemporaryBlockRecord {
        private final String blockId;
        private final String sourceNodeId;
        private final String targetNodeId;
        private final String firewallRuleId;
        private final int startTick;
        private final int durationTicks;

        public TemporaryBlockRecord(String blockId, String sourceNodeId, String targetNodeId,
                                    String firewallRuleId, int startTick, int durationTicks) {
            this.blockId = blockId;
            this.sourceNodeId = sourceNodeId;
            this.targetNodeId = targetNodeId;
            this.firewallRuleId = firewallRuleId;
            this.startTick = startTick;
            this.durationTicks = durationTicks;
        }

        public String getBlockId() { return blockId; }
        public String getSourceNodeId() { return sourceNodeId; }
        public String getTargetNodeId() { return targetNodeId; }
        public String getFirewallRuleId() { return firewallRuleId; }
        public int getStartTick() { return startTick; }
        public int getDurationTicks() { return durationTicks; }
        public int getExpiryTick() { return startTick + durationTicks; }
        public boolean isExpired(int currentTick) { return currentTick >= getExpiryTick(); }

        @Override
        public String toString() {
            return String.format("[%s] %s -> %s (Rule: %s, Start: %d, Duration: %d ticks)",
                    blockId, sourceNodeId, targetNodeId, firewallRuleId, startTick, durationTicks);
        }
    }

    /**
     * Constructs a DefenseContext wrapping the simulation components.
     *
     * @param network  the authoritative virtual network instance
     * @param topology the active network topology instance
     * @throws IllegalArgumentException if either reference is null
     */
    public DefenseContext(VirtualNetwork network, NetworkTopology topology) {
        if (network == null) {
            throw new IllegalArgumentException("VirtualNetwork cannot be null in DefenseContext.");
        }
        if (topology == null) {
            throw new IllegalArgumentException("NetworkTopology cannot be null in DefenseContext.");
        }
        this.network = network;
        this.topology = topology;
    }

    // ---------------------------------------------------------------
    // Simulation Model Accessors & Helpers
    // ---------------------------------------------------------------

    public VirtualNetwork getNetwork() {
        return network;
    }

    public NetworkTopology getTopology() {
        return topology;
    }

    /**
     * Validates whether a device exists in the virtual network registry.
     */
    public boolean isValidDevice(String nodeId) {
        if (nodeId == null || nodeId.trim().isEmpty()) return false;
        return network.containsDevice(nodeId.trim());
    }

    /**
     * Finds a registered device by its ID.
     */
    public Optional<NetworkNode> findDevice(String nodeId) {
        if (nodeId == null) return Optional.empty();
        return network.findDeviceById(nodeId.trim());
    }

    /**
     * Finds an existing connection between source and target devices.
     */
    public Optional<NetworkConnection> findConnectionBetween(String sourceId, String targetId) {
        if (sourceId == null || targetId == null) return Optional.empty();
        String src = sourceId.trim();
        String tgt = targetId.trim();

        for (NetworkConnection conn : topology.getAllConnections()) {
            if (conn.getSourceNodeId().equalsIgnoreCase(src) &&
                conn.getTargetNodeId().equalsIgnoreCase(tgt)) {
                return Optional.of(conn);
            }
        }
        return Optional.empty();
    }

    // ---------------------------------------------------------------
    // Temporary Block Management (Simulated Expiration)
    // ---------------------------------------------------------------

    /**
     * Registers a temporary block record.
     */
    public void registerTemporaryBlock(TemporaryBlockRecord record) {
        if (record != null) {
            activeTemporaryBlocks.put(record.getBlockId(), record);
        }
    }

    /**
     * Advances the simulated clock tick by the specified amount.
     */
    public void advanceTick(int ticks) {
        if (ticks > 0) {
            this.simulationTick += ticks;
        }
    }

    public int getSimulationTick() {
        return simulationTick;
    }

    /**
     * Returns an unmodifiable view of all active temporary blocks.
     */
    public List<TemporaryBlockRecord> getActiveTemporaryBlocks() {
        return Collections.unmodifiableList(new ArrayList<>(activeTemporaryBlocks.values()));
    }

    /**
     * Evaluates and removes expired temporary blocks, returning the list of expired records.
     * Defensive strategies can use this to restore permissions cleanly.
     *
     * @return list of expired TemporaryBlockRecord objects
     */
    public List<TemporaryBlockRecord> purgeExpiredBlocks() {
        List<TemporaryBlockRecord> expiredList = new ArrayList<>();
        Iterator<Map.Entry<String, TemporaryBlockRecord>> iterator = activeTemporaryBlocks.entrySet().iterator();

        while (iterator.hasNext()) {
            Map.Entry<String, TemporaryBlockRecord> entry = iterator.next();
            TemporaryBlockRecord record = entry.getValue();
            if (record.isExpired(simulationTick)) {
                expiredList.add(record);
                iterator.remove();
            }
        }

        return expiredList;
    }
}
