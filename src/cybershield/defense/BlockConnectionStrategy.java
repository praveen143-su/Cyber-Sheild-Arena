package cybershield.defense;

import cybershield.network.ConnectionStatus;
import cybershield.network.NetworkConnection;
import cybershield.network.NetworkTopology;
import cybershield.security.FirewallAction;
import cybershield.security.FirewallRule;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * BlockConnectionStrategy — CyberShield Arena Phase 6
 *
 * OOP Concepts demonstrated:
 *   - Polymorphism     : Implements DefenseStrategy, fulfilling the common execution contract.
 *   - Idempotence      : Detects and safely rejects duplicate block attempts on already-blocked connections.
 *   - Defense in Depth : Blocks the existing active connection and installs a priority firewall rule
 *                        to drop future packets between the specific source and target.
 */
public class BlockConnectionStrategy implements DefenseStrategy {

    private static final AtomicInteger RULE_COUNTER = new AtomicInteger(100);

    @Override
    public DefenseResult execute(DefenseContext context, String targetId, String alertId, String reason) {
        if (context == null) {
            return DefenseResult.failure(DefenseActionType.BLOCK_CONNECTION, alertId, targetId,
                    "Execution failed", "DefenseContext is null.");
        }
        if (targetId == null || targetId.trim().isEmpty()) {
            return DefenseResult.failure(DefenseActionType.BLOCK_CONNECTION, alertId, "UNKNOWN",
                    "Execution failed", "Target identifier is blank.");
        }

        String target = targetId.trim();
        NetworkTopology topology = context.getTopology();

        // Case 1: Target is an existing Connection ID (e.g. "CONN-001")
        Optional<NetworkConnection> connOpt = topology.findConnection(target);
        if (connOpt.isPresent()) {
            NetworkConnection conn = connOpt.get();
            if (conn.isBlocked()) {
                return DefenseResult.failure(DefenseActionType.BLOCK_CONNECTION, alertId, target,
                        "Block rejected", "Connection " + target + " is already blocked.");
            }

            // Block the active connection
            topology.blockConnection(target);

            // Install persistent blocking firewall rule to prevent re-establishment
            String fwRuleId = String.format("FW-DEF-%03d", RULE_COUNTER.getAndIncrement());
            FirewallRule blockRule = new FirewallRule(
                    fwRuleId,
                    conn.getSourceNodeId(),
                    conn.getTargetNodeId(),
                    FirewallAction.BLOCK
            );
            topology.addFirewallRuleFirst(blockRule);

            String desc = String.format("Blocked connection %s (%s -> %s) and installed firewall rule %s. Reason: %s",
                    target, conn.getSourceNodeId(), conn.getTargetNodeId(), fwRuleId,
                    (reason != null ? reason : "Automated policy response"));
            return DefenseResult.success(DefenseActionType.BLOCK_CONNECTION, alertId, target, desc);
        }

        // Case 2: Target is formatted as "sourceId->targetId" (e.g. "WS-001->SRV-001")
        if (target.contains("->")) {
            String[] parts = target.split("->");
            if (parts.length == 2) {
                String src = parts[0].trim();
                String tgt = parts[1].trim();

                if (!context.isValidDevice(src) || !context.isValidDevice(tgt)) {
                    return DefenseResult.failure(DefenseActionType.BLOCK_CONNECTION, alertId, target,
                            "Block failed", "One or both devices in endpoint route do not exist.");
                }

                // Block any existing connection between endpoints
                Optional<NetworkConnection> liveConn = context.findConnectionBetween(src, tgt);
                liveConn.ifPresent(c -> topology.blockConnection(c.getConnectionId()));

                // Inject blocking firewall rule at index 0
                String fwRuleId = String.format("FW-DEF-%03d", RULE_COUNTER.getAndIncrement());
                FirewallRule blockRule = new FirewallRule(fwRuleId, src, tgt, FirewallAction.BLOCK);
                topology.addFirewallRuleFirst(blockRule);

                String desc = String.format("Enforced connection block %s -> %s via firewall rule %s. Reason: %s",
                        src, tgt, fwRuleId, (reason != null ? reason : "Automated policy response"));
                return DefenseResult.success(DefenseActionType.BLOCK_CONNECTION, alertId, target, desc);
            }
        }

        return DefenseResult.failure(DefenseActionType.BLOCK_CONNECTION, alertId, target,
                "Block failed", "Connection or endpoint pair '" + target + "' does not exist in network topology.");
    }

    @Override
    public String getStrategyName() {
        return "Block Connection Strategy";
    }

    @Override
    public DefenseActionType getActionType() {
        return DefenseActionType.BLOCK_CONNECTION;
    }
}
