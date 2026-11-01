package cybershield.defense;

import cybershield.model.NetworkNode;
import cybershield.network.NetworkConnection;
import cybershield.network.NetworkTopology;

import java.util.List;
import java.util.Optional;

/**
 * IsolateDeviceStrategy — CyberShield Arena Phase 6
 *
 * OOP Concepts demonstrated:
 *   - Polymorphism           : Implements DefenseStrategy interface.
 *   - Non-Destructive State  : Quarantines the device via setIsolated(true) while preserving its
 *                              underlying operational status (ONLINE/OFFLINE) intact.
 *   - Isolation Containment  : Blocks all existing active simulated connections connected to this device,
 *                              and topology prevents any new connections to/from it.
 *   - Validation & Guarding  : Rejects requests for nonexistent or already-isolated devices.
 */
public class IsolateDeviceStrategy implements DefenseStrategy {

    @Override
    public DefenseResult execute(DefenseContext context, String targetId, String alertId, String reason) {
        if (context == null) {
            return DefenseResult.failure(DefenseActionType.ISOLATE_DEVICE, alertId, targetId,
                    "Isolation failed", "DefenseContext is null.");
        }
        if (targetId == null || targetId.trim().isEmpty()) {
            return DefenseResult.failure(DefenseActionType.ISOLATE_DEVICE, alertId, "UNKNOWN",
                    "Isolation failed", "Target device identifier is blank.");
        }

        String nodeId = targetId.trim();
        Optional<NetworkNode> deviceOpt = context.findDevice(nodeId);

        if (deviceOpt.isEmpty()) {
            return DefenseResult.failure(DefenseActionType.ISOLATE_DEVICE, alertId, nodeId,
                    "Isolation rejected", "Device '" + nodeId + "' is not registered in virtual network.");
        }

        NetworkNode device = deviceOpt.get();

        if (device.isIsolated()) {
            return DefenseResult.failure(DefenseActionType.ISOLATE_DEVICE, alertId, nodeId,
                    "Isolation rejected", "Device '" + nodeId + "' (" + device.getNodeName() + ") is already isolated.");
        }

        // 1. Mark device as isolated in simulation
        device.setIsolated(true);

        // 2. Enforce containment: block all currently active connections involving this device
        NetworkTopology topology = context.getTopology();
        List<NetworkConnection> affectedConnections = topology.getConnectionsForDevice(nodeId);
        int blockedCount = 0;

        for (NetworkConnection conn : affectedConnections) {
            if (conn.isActive()) {
                conn.block();
                blockedCount++;
            }
        }

        String description = String.format(
                "Device '%s' (%s) successfully ISOLATED. Blocked %d active connection(s). Reason: %s",
                nodeId, device.getNodeName(), blockedCount,
                (reason != null ? reason : "Critical security isolation policy triggered")
        );

        return DefenseResult.success(DefenseActionType.ISOLATE_DEVICE, alertId, nodeId, description);
    }

    @Override
    public String getStrategyName() {
        return "Isolate Device Strategy";
    }

    @Override
    public DefenseActionType getActionType() {
        return DefenseActionType.ISOLATE_DEVICE;
    }
}
