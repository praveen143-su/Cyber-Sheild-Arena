package cybershield.defense;

import cybershield.network.NetworkConnection;
import cybershield.network.NetworkTopology;
import cybershield.security.FirewallAction;
import cybershield.security.FirewallRule;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * TemporaryBlockStrategy — CyberShield Arena Phase 6
 *
 * OOP Concepts demonstrated:
 *   - Polymorphism        : Implements DefenseStrategy interface.
 *   - Temporal Abstraction: Uses simulation ticks instead of nondeterministic system clocks/threads.
 *   - Policy Preservation : Upon expiration, re-evaluates baseline firewall rules to ensure that
 *                           independent baseline firewall blocks are NEVER silently overwritten.
 */
public class TemporaryBlockStrategy implements DefenseStrategy {

    public static final int DEFAULT_DURATION_TICKS = 10;
    private static final AtomicInteger TEMP_COUNTER = new AtomicInteger(1);

    private final int configuredDurationTicks;

    public TemporaryBlockStrategy() {
        this(DEFAULT_DURATION_TICKS);
    }

    public TemporaryBlockStrategy(int durationTicks) {
        if (durationTicks <= 0) {
            throw new IllegalArgumentException("Duration ticks must be positive (got " + durationTicks + ").");
        }
        this.configuredDurationTicks = durationTicks;
    }

    @Override
    public DefenseResult execute(DefenseContext context, String targetId, String alertId, String reason) {
        if (context == null) {
            return DefenseResult.failure(DefenseActionType.TEMPORARY_BLOCK, alertId, targetId,
                    "Temporary block failed", "DefenseContext is null.");
        }
        if (targetId == null || targetId.trim().isEmpty()) {
            return DefenseResult.failure(DefenseActionType.TEMPORARY_BLOCK, alertId, "UNKNOWN",
                    "Temporary block failed", "Target identifier is blank.");
        }

        String target = targetId.trim();
        NetworkTopology topology = context.getTopology();
        String srcNodeId = null;
        String tgtNodeId = null;
        String connId = null;

        // Resolve endpoints from connection or formatted pair
        Optional<NetworkConnection> connOpt = topology.findConnection(target);
        if (connOpt.isPresent()) {
            NetworkConnection conn = connOpt.get();
            connId = conn.getConnectionId();
            srcNodeId = conn.getSourceNodeId();
            tgtNodeId = conn.getTargetNodeId();
        } else if (target.contains("->")) {
            String[] parts = target.split("->");
            if (parts.length == 2) {
                srcNodeId = parts[0].trim();
                tgtNodeId = parts[1].trim();
                Optional<NetworkConnection> c = context.findConnectionBetween(srcNodeId, tgtNodeId);
                if (c.isPresent()) {
                    connId = c.get().getConnectionId();
                }
            }
        }

        if (srcNodeId == null || tgtNodeId == null || !context.isValidDevice(srcNodeId) || !context.isValidDevice(tgtNodeId)) {
            return DefenseResult.failure(DefenseActionType.TEMPORARY_BLOCK, alertId, target,
                    "Temporary block failed", "Target '" + target + "' does not resolve to valid registered devices.");
        }

        // Apply active block to connection if exists
        if (connId != null) {
            topology.blockConnection(connId);
        }

        // Install high-priority temporary firewall drop rule
        String tempBlockId = String.format("TBL-%04d", TEMP_COUNTER.getAndIncrement());
        String fwRuleId = "FW-TMP-" + tempBlockId;
        FirewallRule tempRule = new FirewallRule(fwRuleId, srcNodeId, tgtNodeId, FirewallAction.BLOCK);
        topology.addFirewallRuleFirst(tempRule);

        // Record temporary block in DefenseContext
        int currentTick = context.getSimulationTick();
        DefenseContext.TemporaryBlockRecord record = new DefenseContext.TemporaryBlockRecord(
                tempBlockId, srcNodeId, tgtNodeId, fwRuleId, currentTick, configuredDurationTicks
        );
        context.registerTemporaryBlock(record);

        String description = String.format(
                "Applied temporary block [%s] on %s -> %s for %d ticks (Expires at tick %d). Rule: %s. Reason: %s",
                tempBlockId, srcNodeId, tgtNodeId, configuredDurationTicks,
                (currentTick + configuredDurationTicks), fwRuleId,
                (reason != null ? reason : "Suspicious activity response")
        );

        return DefenseResult.success(DefenseActionType.TEMPORARY_BLOCK, alertId, target, description);
    }

    /**
     * Explicit expiration processor. Evaluates expired temporary blocks, removes temporary rules,
     * and safely restores connection state only if independent baseline firewall rules allow it.
     *
     * @param context active simulation context
     * @return list of DefenseResult objects summarizing expired blocks and their restorations
     */
    public List<DefenseResult> processExpirations(DefenseContext context) {
        List<DefenseResult> results = new ArrayList<>();
        if (context == null) return results;

        List<DefenseContext.TemporaryBlockRecord> expired = context.purgeExpiredBlocks();
        NetworkTopology topology = context.getTopology();

        for (DefenseContext.TemporaryBlockRecord record : expired) {
            // 1. Remove the temporary firewall rule
            topology.removeFirewallRule(record.getFirewallRuleId());

            // 2. Re-evaluate baseline firewall policy
            FirewallAction baselineAction = topology.evaluateFirewall(
                    record.getSourceNodeId(), record.getTargetNodeId()
            );

            Optional<NetworkConnection> conn = context.findConnectionBetween(
                    record.getSourceNodeId(), record.getTargetNodeId()
            );

            if (baselineAction == FirewallAction.ALLOW) {
                // Safe to restore connection
                conn.ifPresent(c -> topology.unblockConnection(c.getConnectionId()));
                results.add(DefenseResult.success(
                        DefenseActionType.RESTORE_DEVICE,
                        "N/A",
                        record.getSourceNodeId() + "->" + record.getTargetNodeId(),
                        "Temporary block " + record.getBlockId() + " expired. Baseline policy allows traffic; connection restored to ACTIVE."
                ));
            } else {
                // Baseline policy independent rule blocks traffic — preserve block
                results.add(DefenseResult.success(
                        DefenseActionType.ALERT_ONLY,
                        "N/A",
                        record.getSourceNodeId() + "->" + record.getTargetNodeId(),
                        "Temporary block " + record.getBlockId() + " expired and removed, but baseline firewall still specifies BLOCK. Connection remains blocked."
                ));
            }
        }

        return results;
    }

    public int getConfiguredDurationTicks() {
        return configuredDurationTicks;
    }

    @Override
    public String getStrategyName() {
        return "Temporary Block Strategy";
    }

    @Override
    public DefenseActionType getActionType() {
        return DefenseActionType.TEMPORARY_BLOCK;
    }
}
