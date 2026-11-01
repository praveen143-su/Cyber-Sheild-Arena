package cybershield.network;

import cybershield.model.DeviceStatus;
import cybershield.model.NetworkNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * VirtualNetwork — CyberShield Arena Phase 2
 *
 * OOP Concepts demonstrated:
 *   - Encapsulation     : Internal data structures (Maps/Lists) are strictly private.
 *   - Information Hiding: Returns unmodifiable collections (Collections.unmodifiableList).
 *   - Defensive Checks  : Enforces uniqueness for both Node IDs and IP addresses.
 *   - Observer Pattern  : Allows listeners (like NetworkTopology) to be notified on device removal.
 *
 * Serves as the central registry and authoritative repository of all network devices.
 */
public class VirtualNetwork {

    /** Map of Node ID -> NetworkNode instance (maintains insertion order). */
    private final Map<String, NetworkNode> devicesById = new LinkedHashMap<>();

    /** Secondary index: IP Address -> Node ID to guarantee uniqueness and fast O(1) lookup. */
    private final Map<String, String> ipToIdMap = new LinkedHashMap<>();

    /** Listeners triggered whenever a device is removed from the network. */
    private final List<Consumer<String>> deviceRemovalListeners = new ArrayList<>();

    public VirtualNetwork() {
        // Default constructor
    }

    // ---------------------------------------------------------------
    // Device Registration & Management
    // ---------------------------------------------------------------

    /**
     * Registers a device into the virtual network.
     * Enforces non-null checks, duplicate nodeId checks, and duplicate IP address checks.
     *
     * @param device the NetworkNode to register
     * @throws IllegalArgumentException if device is null, or if nodeId or IP already exists
     */
    public void registerDevice(NetworkNode device) {
        if (device == null) {
            throw new IllegalArgumentException("Cannot register a null device.");
        }

        String nodeId = device.getNodeId();
        String ipAddress = device.getIpAddress();

        if (devicesById.containsKey(nodeId)) {
            throw new IllegalArgumentException("Duplicate Node ID rejected: A device with ID '" +
                    nodeId + "' already exists in the virtual network.");
        }

        if (ipToIdMap.containsKey(ipAddress)) {
            String existingNodeId = ipToIdMap.get(ipAddress);
            throw new IllegalArgumentException("Duplicate IP Address rejected: IP '" +
                    ipAddress + "' is already assigned to node '" + existingNodeId + "'.");
        }

        devicesById.put(nodeId, device);
        ipToIdMap.put(ipAddress, nodeId);
        System.out.println("[VirtualNetwork] Registered: " + device.getNodeName() +
                " (ID: " + nodeId + ", IP: " + ipAddress + ")");
    }

    /**
     * Removes a device from the virtual network by its Node ID.
     * Also removes its IP mapping and notifies any registered listeners (e.g. topology).
     *
     * @param nodeId identifier of device to remove
     * @return true if device was found and removed, false otherwise
     */
    public boolean removeDevice(String nodeId) {
        if (nodeId == null || !devicesById.containsKey(nodeId.trim())) {
            return false;
        }

        String id = nodeId.trim();
        NetworkNode removed = devicesById.remove(id);
        ipToIdMap.remove(removed.getIpAddress());

        System.out.println("[VirtualNetwork] Removed device: " + removed.getNodeName() + " (" + id + ")");

        // Notify subscribers (e.g. topology to clean up connections)
        for (Consumer<String> listener : deviceRemovalListeners) {
            try {
                listener.accept(id);
            } catch (Exception e) {
                System.err.println("[VirtualNetwork] Error notifying removal listener: " + e.getMessage());
            }
        }

        return true;
    }

    /**
     * Registers a listener callback that gets invoked whenever a device is removed.
     *
     * @param listener consumer receiving the removed nodeId
     */
    public void onDeviceRemoved(Consumer<String> listener) {
        if (listener != null) {
            deviceRemovalListeners.add(listener);
        }
    }

    // ---------------------------------------------------------------
    // Search & Retrieval (Polymorphic Queries)
    // ---------------------------------------------------------------

    /**
     * Finds a device by its Node ID.
     *
     * @param nodeId node identifier
     * @return Optional containing the device if found, or empty Optional
     */
    public Optional<NetworkNode> findDeviceById(String nodeId) {
        if (nodeId == null) return Optional.empty();
        return Optional.ofNullable(devicesById.get(nodeId.trim()));
    }

    /**
     * Finds a device by its IPv4 address.
     *
     * @param ipAddress IP address string
     * @return Optional containing the device if found, or empty Optional
     */
    public Optional<NetworkNode> findDeviceByIp(String ipAddress) {
        if (ipAddress == null) return Optional.empty();
        String foundId = ipToIdMap.get(ipAddress.trim());
        if (foundId == null) return Optional.empty();
        return Optional.ofNullable(devicesById.get(foundId));
    }

    /**
     * Checks if a device with given Node ID exists.
     *
     * @param nodeId identifier to check
     * @return true if present
     */
    public boolean containsDevice(String nodeId) {
        if (nodeId == null) return false;
        return devicesById.containsKey(nodeId.trim());
    }

    // ---------------------------------------------------------------
    // Aggregation & Statistics
    // ---------------------------------------------------------------

    public int getTotalDeviceCount() {
        return devicesById.size();
    }

    public int getOnlineDeviceCount() {
        int count = 0;
        for (NetworkNode node : devicesById.values()) {
            if (node.getStatus() == DeviceStatus.ONLINE) {
                count++;
            }
        }
        return count;
    }

    public int getOfflineDeviceCount() {
        int count = 0;
        for (NetworkNode node : devicesById.values()) {
            if (node.getStatus() == DeviceStatus.OFFLINE) {
                count++;
            }
        }
        return count;
    }

    /**
     * Returns an unmodifiable view of all registered devices.
     * Protects internal collection against external mutations.
     *
     * @return unmodifiable List of NetworkNode
     */
    public List<NetworkNode> getAllDevices() {
        return Collections.unmodifiableList(new ArrayList<>(devicesById.values()));
    }

    // ---------------------------------------------------------------
    // Display & Reporting
    // ---------------------------------------------------------------

    /**
     * Prints a formatted summary table of all registered devices in the network.
     */
    public void displayAllDevices() {
        System.out.println("\n+------------------------------------------------------------------------------------+");
        System.out.printf("| %-72s |\n", "VIRTUAL NETWORK DEVICE INVENTORY (" + getTotalDeviceCount() + " Devices)");
        System.out.println("+------------+-------------------------+-----------------+------------+--------------+");
        System.out.printf("| %-10s | %-23s | %-15s | %-10s | %-12s |\n",
                "Node ID", "Device Name", "IP Address", "Type", "Status");
        System.out.println("+------------+-------------------------+-----------------+------------+--------------+");

        for (NetworkNode node : devicesById.values()) {
            String type = node.getClass().getSimpleName();
            System.out.printf("| %-10s | %-23s | %-15s | %-10s | %-12s |\n",
                    node.getNodeId(),
                    node.getNodeName(),
                    node.getIpAddress(),
                    type,
                    node.getStatus());
        }

        System.out.println("+------------+-------------------------+-----------------+------------+--------------+");
        System.out.printf("  Summary: Total=%d | Online=%d | Offline=%d\n\n",
                getTotalDeviceCount(), getOnlineDeviceCount(), getOfflineDeviceCount());
    }
}
