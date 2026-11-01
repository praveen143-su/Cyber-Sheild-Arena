package cybershield.defense;

import cybershield.ml.ThreatPrediction;
import cybershield.monitoring.AlertManager;
import cybershield.monitoring.SecurityAlert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * DefenseCoordinator — CyberShield Arena Phase 6
 *
 * OOP Concepts demonstrated:
 *   - Facade / Mediator Pattern : Serves as the central coordination hub tying together
 *                                 AlertManager (Phase 4), ML ThreatPrediction (Phase 5),
 *                                 IncidentResponseManager, DefenseAgent, and DefenseAuditLogger.
 *   - Separation of Concerns   : Main.java acts purely as an entry orchestrator;
 *                                DefenseCoordinator encapsulates the end-to-end response flow.
 */
public class DefenseCoordinator {

    private final DefenseAgent defenseAgent;
    private final IncidentResponseManager incidentManager;
    private final DefenseAuditLogger auditLogger;

    public DefenseCoordinator(DefenseAgent defenseAgent,
                              IncidentResponseManager incidentManager,
                              DefenseAuditLogger auditLogger) {
        if (defenseAgent == null) {
            throw new IllegalArgumentException("DefenseAgent cannot be null for DefenseCoordinator.");
        }
        if (incidentManager == null) {
            throw new IllegalArgumentException("IncidentResponseManager cannot be null for DefenseCoordinator.");
        }
        if (auditLogger == null) {
            throw new IllegalArgumentException("DefenseAuditLogger cannot be null for DefenseCoordinator.");
        }
        this.defenseAgent = defenseAgent;
        this.incidentManager = incidentManager;
        this.auditLogger = auditLogger;
    }

    /**
     * Coordinates the defensive response for a batch of security alerts and optional ML predictions.
     *
     * @param alerts          list of security alerts from AlertManager
     * @param predictionsList list of ML predictions (can be null or empty)
     * @return list of DefenseResult objects detailing actions taken
     */
    public List<DefenseResult> coordinateResponses(List<SecurityAlert> alerts, List<ThreatPrediction> predictionsList) {
        List<DefenseResult> results = new ArrayList<>();
        if (alerts == null || alerts.isEmpty()) {
            return results;
        }

        // Index ML predictions by eventId for fast O(1) lookup
        Map<String, ThreatPrediction> predictionMap = new HashMap<>();
        if (predictionsList != null) {
            for (ThreatPrediction pred : predictionsList) {
                if (pred != null && pred.getEventId() != null) {
                    predictionMap.put(pred.getEventId(), pred);
                }
            }
        }

        for (SecurityAlert alert : alerts) {
            ThreatPrediction matchingPrediction = predictionMap.get(alert.getEventId());
            DefenseResult result = processAlert(alert, matchingPrediction);
            results.add(result);
        }

        return Collections.unmodifiableList(results);
    }

    /**
     * Processes a single alert end-to-end:
     * 1. Creates/updates incident
     * 2. Triage & policy evaluation via DefenseAgent
     * 3. Executes simulated defense strategy
     * 4. Updates incident status (CONTAINED if successful active action)
     * 5. Appends record to audit log
     *
     * @param alert      the security alert
     * @param prediction matching ML threat prediction (optional)
     * @return outcome of the defensive response
     */
    public DefenseResult processAlert(SecurityAlert alert, ThreatPrediction prediction) {
        if (alert == null) {
            return DefenseResult.failure(DefenseActionType.ALERT_ONLY, "N/A", "UNKNOWN",
                    "Processing skipped", "Alert was null.");
        }

        // 1. Create or correlate incident
        SecurityIncident incident = incidentManager.createOrUpdateIncident(alert);
        incident.markInvestigating("Evaluating automated defense policy");

        // 2. Ask DefenseAgent to select and execute the policy-defined response
        DefenseResult result = defenseAgent.respondToAlert(alert, prediction);

        // 3. Log to audit file
        auditLogger.logAction(result, incident.getIncidentId());

        // 4. Update incident status based on outcome
        if (result.isSuccess()) {
            if (result.getActionType() == DefenseActionType.BLOCK_CONNECTION ||
                result.getActionType() == DefenseActionType.TEMPORARY_BLOCK ||
                result.getActionType() == DefenseActionType.ISOLATE_DEVICE) {
                try {
                    incident.markContained(result);
                } catch (IllegalStateException e) {
                    incident.addAuditNote("Containment update error: " + e.getMessage());
                }
            } else {
                incident.addAuditNote("Monitored alert under ALERT_ONLY policy.");
            }
        } else {
            incident.addAuditNote("Defense action could not be completed: " + result.getFailureReason());
        }

        return result;
    }

    /**
     * Executes recovery and restoration for an isolated device.
     *
     * @param incidentId ID of the security incident undergoing remediation
     * @param nodeId     ID of the device to restore
     * @param reason     justification for restoration
     * @return outcome of the recovery action
     */
    public DefenseResult recoverDevice(String incidentId, String nodeId, String reason) {
        DefenseResult recoveryResult = defenseAgent.executeRecovery(nodeId, reason);

        // Record to audit logger
        auditLogger.logAction(recoveryResult, incidentId);

        // Update incident status if present
        Optional<SecurityIncident> incOpt = incidentManager.findIncidentById(incidentId);
        if (incOpt.isPresent()) {
            SecurityIncident inc = incOpt.get();
            if (recoveryResult.isSuccess()) {
                try {
                    inc.markRecovered(recoveryResult);
                } catch (IllegalStateException e) {
                    inc.addAuditNote("Recovery state error: " + e.getMessage());
                }
            } else {
                inc.addAuditNote("Recovery failed: " + recoveryResult.getFailureReason());
            }
        }

        return recoveryResult;
    }

    // ---------------------------------------------------------------
    // Getters & Monitoring Display
    // ---------------------------------------------------------------

    public DefenseAgent getDefenseAgent() {
        return defenseAgent;
    }

    public IncidentResponseManager getIncidentManager() {
        return incidentManager;
    }

    public DefenseAuditLogger getAuditLogger() {
        return auditLogger;
    }

    public void displayDefenseDashboard() {
        incidentManager.displayIncidentSummary();

        System.out.println("+--------------------------------------------------------------------------------------------------------------------+");
        System.out.printf("| %-114s |\n", "DEFENSE AUDIT TRAIL SUMMARY (" + defenseAgent.getResponseHistory().size() + " Actions Processed)");
        System.out.println("+----------+----------------------+----------+----------+---------+--------------------------------------------------+");
        System.out.printf("| %-8s | %-20s | %-8s | %-8s | %-7s | %-48s |\n",
                "Act ID", "Action Type", "Alert ID", "Target", "Success", "Result Details");
        System.out.println("+----------+----------------------+----------+----------+---------+--------------------------------------------------+");

        for (DefenseResult res : defenseAgent.getResponseHistory()) {
            String desc = res.getResultDescription();
            if (desc.length() > 48) {
                desc = desc.substring(0, 45) + "...";
            }
            System.out.printf("| %-8s | %-20s | %-8s | %-8s | %-7s | %-48s |\n",
                    res.getActionId(),
                    res.getActionType().name(),
                    res.getAlertId(),
                    res.getTargetId(),
                    res.isSuccess(),
                    desc);
        }

        System.out.println("+----------+----------------------+----------+----------+---------+--------------------------------------------------+\n");
    }
}
