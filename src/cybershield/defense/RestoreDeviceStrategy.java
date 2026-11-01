package cybershield.defense;

import cybershield.model.DeviceStatus;
import cybershield.model.NetworkNode;
import cybershield.network.NetworkConnection;
import cybershield.network.NetworkTopology;
import cybershield.security.FirewallAction;

import java.util.List;
import java.util.Optional;

/**
 * RestoreDeviceStrategy — CyberShield Arena Phase 6
 *
 * OOP Concepts demonstrated:
 *   - Polymorphism            : Implements DefenseStrategy interface.
 *   - Remediation / Recovery  : Clears isolation status on the node.
 *   - Policy Preservation     : Re-evaluates firewall rules before unblocking any connection;
 *                               independent firewall BLOCK policies are never overridden.
 *   - Guarded State Transition: Rejects restoration requests for devices not currently isolated.
 */
public class RestoreDeviceStrategy implements DefenseStrategy {

    @Override
    public DefenseResult execute(DefenseContext context, String targetId, String alertId, String reason) {
        if (context == null) {
            return DefenseResult.failure(DefenseActionType.RESTORE_DEVICE, alertId, targetId,
                    "Restoration failed", "DefenseContext is null.");
        }
        if (targetId == null || targetId.trim().isEmpty()) {
            return DefenseResult.failure(DefenseActionType.RESTORE_DEVICE, alertId, "UNKNOWN",
                    "Restoration failed", "Target device identifier is blank.");
        }

        String nodeId = targetId.trim();
        Optional<NetworkNode> deviceOpt = context.findDevice(nodeId);

        if (deviceOpt.isEmpty()) {
            return DefenseResult.failure(DefenseActionType.RESTORE_DEVICE, alertId, nodeId,
                    "Restoration rejected", "Device '" + nodeId + "' is not registered in virtual network.");
        }

        NetworkNode device = deviceOpt.get();

        if (!device.isIsolated()) {
            return DefenseResult.failure(DefenseActionType.RESTORE_DEVICE, alertId, nodeId,
                    "Restoration rejected", "Device '" + nodeId + "' (" + device.getNodeName() + ") is NOT currently isolated.");
        }

        // 1. Remove simulated isolation status
        device.setIsolated(false);

        // 2. Re-evaluate existing connections involving this device against active firewall policies
        NetworkTopology topology = context.getTopology();
        List<NetworkConnection> connections = topology.getConnectionsForDevice(nodeId);
        int restoredCount = 0;
        int preservedBlockedCount = 0;

        for (NetworkConnection conn : connections) {
            if (conn.isBlocked()) {
                FirewallAction action = topology.evaluateFirewall(conn.getSourceNodeId(), conn.getTargetNodeId());

                // Find both endpoints to ensure neither is offline or isolated
                Optional<NetworkNode> srcOpt = context.findDevice(conn.getSourceNodeId());
                Optional<NetworkNode> tgtOpt = context.findDevice(conn.getTargetNodeId());

                boolean endpointsHealthy = srcOpt.isPresent() && tgtOpt.isPresent()
                        && srcOpt.get().getStatus() == DeviceStatus.ONLINE
                        && tgtOpt.get().getStatus() == DeviceStatus.ONLINE
                        && !srcOpt.get().isIsolated()
                        && !tgtOpt.get().isIsolated();

                if (action == FirewallAction.ALLOW && endpointsHealthy) {
                    conn.activate();
                    restoredCount++;
                } else {
                    // Retain block because firewall rules or endpoint states require it
                    preservedBlockedCount++;
                }
            }
        }

        String description = String.format(
                "Device '%s' restored from isolation. Re-evaluated connections: %d restored to ACTIVE, %d maintained as BLOCKED by firewall. Reason: %s",
                nodeId, restoredCount, preservedBlockedCount,
                (reason != null ? reason : "Incident containment resolved and operational clearance verified")
        );

        return DefenseResult.success(DefenseActionType.RESTORE_DEVICE, alertId, nodeId, description);
    }

    @Override
    public String getStrategyName() {
        return "Restore Device Strategy";
    }

    @Override
    public DefenseActionType getActionType() {
        return DefenseActionType.RESTORE_DEVICE;
    }
}
