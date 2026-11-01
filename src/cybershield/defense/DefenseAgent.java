package cybershield.defense;

import cybershield.ml.ThreatPrediction;
import cybershield.monitoring.SecurityAlert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * DefenseAgent — CyberShield Arena Phase 6
 *
 * OOP Concepts demonstrated:
 *   - Polymorphism          : Dispatches commands to different DefenseStrategy implementations
 *                             through the common DefenseStrategy interface without knowing concrete types.
 *   - Dependency Injection  : Accepts DefenseContext and DefensePolicy via constructor.
 *   - Open-Closed Principle : New strategies can be registered dynamically via registerStrategy().
 *   - Idempotence / Dedup   : Prevents duplicate execution of identical actions for the same alert.
 *   - Dry-Run Simulation   : Allows safety evaluations without modifying virtual network state.
 */
public class DefenseAgent {

    private final DefenseContext context;
    private final DefensePolicy policy;
    private final Map<DefenseActionType, DefenseStrategy> strategyRegistry = new EnumMap<>(DefenseActionType.class);

    private boolean dryRunMode = false;
    private final Set<String> executedActionDedupSet = new HashSet<>();
    private final List<DefenseResult> responseHistory = new ArrayList<>();

    public DefenseAgent(DefenseContext context, DefensePolicy policy) {
        if (context == null) {
            throw new IllegalArgumentException("DefenseContext cannot be null for DefenseAgent.");
        }
        if (policy == null) {
            throw new IllegalArgumentException("DefensePolicy cannot be null for DefenseAgent.");
        }
        this.context = context;
        this.policy = policy;

        // Register default polymorphic defense strategies
        registerStrategy(new BlockConnectionStrategy());
        registerStrategy(new TemporaryBlockStrategy());
        registerStrategy(new IsolateDeviceStrategy());
        registerStrategy(new RestoreDeviceStrategy());
    }

    /**
     * Registers a defense strategy in the agent's dispatch table.
     * Demonstrates the Open-Closed Principle.
     *
     * @param strategy the DefenseStrategy implementation to register
     */
    public void registerStrategy(DefenseStrategy strategy) {
        if (strategy != null) {
            strategyRegistry.put(strategy.getActionType(), strategy);
        }
    }

    /**
     * Responds to a security alert by consulting the defense policy, corroborating with ML
     * predictions (if present), selecting the appropriate strategy, and executing it polymorphically.
     *
     * @param alert        the triggered SecurityAlert
     * @param mlPrediction optional ThreatPrediction (can be null)
     * @return structured DefenseResult
     */
    public DefenseResult respondToAlert(SecurityAlert alert, ThreatPrediction mlPrediction) {
        if (alert == null) {
            return DefenseResult.failure(DefenseActionType.ALERT_ONLY, "N/A", "UNKNOWN",
                    "Response skipped", "Alert was null.");
        }

        // 1. Consult DefensePolicy
        DefensePolicy.PolicyDecision decision = policy.evaluate(alert, mlPrediction);
        DefenseActionType actionType = decision.getRecommendedAction();

        // Target: prefer connection notation "src->tgt" for blocks; target node for isolation
        String targetId;
        if (actionType == DefenseActionType.ISOLATE_DEVICE || actionType == DefenseActionType.RESTORE_DEVICE) {
            // Isolate the source of the attack or target depending on severity
            targetId = alert.getSourceNodeId();
        } else {
            targetId = alert.getSourceNodeId() + "->" + alert.getTargetNodeId();
        }

        // 2. Handle ALERT_ONLY
        if (actionType == DefenseActionType.ALERT_ONLY) {
            DefenseResult result = DefenseResult.success(
                    DefenseActionType.ALERT_ONLY,
                    alert.getAlertId(),
                    targetId,
                    "Alert-only monitored: " + decision.getRationale()
            );
            recordResult(result);
            return result;
        }

        // 3. Deduplication check: prevent duplicate responses for the same alert + action
        String dedupKey = alert.getAlertId() + "::" + actionType.name() + "::" + targetId;
        if (executedActionDedupSet.contains(dedupKey)) {
            DefenseResult dupResult = DefenseResult.failure(
                    actionType,
                    alert.getAlertId(),
                    targetId,
                    "Duplicate response suppressed",
                    "Action " + actionType + " has already been executed for alert " + alert.getAlertId()
            );
            recordResult(dupResult);
            return dupResult;
        }

        // 4. Dry-run mode check
        if (dryRunMode) {
            DefenseResult dryRunResult = DefenseResult.success(
                    actionType,
                    alert.getAlertId(),
                    targetId,
                    "[DRY-RUN] Planned " + actionType + " on " + targetId + " | Reason: " + decision.getRationale()
            );
            recordResult(dryRunResult);
            return dryRunResult;
        }

        // 5. Manual approval check
        if (decision.isRequiresManualApproval()) {
            DefenseResult deferredResult = DefenseResult.failure(
                    actionType,
                    alert.getAlertId(),
                    targetId,
                    "Action deferred pending administrator authorization",
                    "Policy requires explicit approval for " + actionType + " on " + targetId
            );
            recordResult(deferredResult);
            return deferredResult;
        }

        // 6. Polymorphic strategy dispatch
        DefenseStrategy strategy = strategyRegistry.get(actionType);
        if (strategy == null) {
            DefenseResult missingStrategy = DefenseResult.failure(
                    actionType,
                    alert.getAlertId(),
                    targetId,
                    "Dispatch failed",
                    "No strategy registered for action type " + actionType
            );
            recordResult(missingStrategy);
            return missingStrategy;
        }

        // Execute polymorphically through the common interface
        DefenseResult executionResult = strategy.execute(context, targetId, alert.getAlertId(), decision.getRationale());

        if (executionResult.isSuccess()) {
            executedActionDedupSet.add(dedupKey);
        }

        recordResult(executionResult);
        return executionResult;
    }

    /**
     * Executes an explicit recovery action on a target device.
     */
    public DefenseResult executeRecovery(String nodeId, String reason) {
        DefenseStrategy recoveryStrategy = strategyRegistry.get(DefenseActionType.RESTORE_DEVICE);
        if (recoveryStrategy == null) {
            return DefenseResult.failure(DefenseActionType.RESTORE_DEVICE, "N/A", nodeId,
                    "Recovery failed", "No RestoreDeviceStrategy registered.");
        }
        DefenseResult result = recoveryStrategy.execute(context, nodeId, "RECOVERY", reason);
        recordResult(result);
        return result;
    }

    private void recordResult(DefenseResult result) {
        if (result != null) {
            responseHistory.add(result);
        }
    }

    // ---------------------------------------------------------------
    // Configuration & Inspection
    // ---------------------------------------------------------------

    public boolean isDryRunMode() {
        return dryRunMode;
    }

    public void setDryRunMode(boolean dryRunMode) {
        this.dryRunMode = dryRunMode;
    }

    public DefensePolicy getPolicy() {
        return policy;
    }

    public DefenseContext getContext() {
        return context;
    }

    public List<DefenseResult> getResponseHistory() {
        return Collections.unmodifiableList(responseHistory);
    }
}
