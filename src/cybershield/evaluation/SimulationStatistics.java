package cybershield.evaluation;

import cybershield.defense.DefenseActionType;
import cybershield.defense.DefenseResult;
import cybershield.defense.IncidentStatus;
import cybershield.defense.SecurityIncident;
import cybershield.ml.PredictionClass;
import cybershield.ml.ThreatPrediction;
import cybershield.monitoring.SecurityAlert;
import cybershield.network.NetworkTopology;
import cybershield.network.VirtualNetwork;
import cybershield.security.AttackType;
import cybershield.security.SecurityEvent;
import cybershield.security.Severity;

import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;

/**
 * SimulationStatistics — CyberShield Arena Phase 7
 *
 * OOP Concepts demonstrated:
 *   - Aggregator Pattern : Aggregates multi-phase state into centralized, verifiable analytics.
 *   - Defensive Copying  : Returns unmodifiable views of all statistical distributions.
 *   - Idempotent Counts  : Uses EnumMaps initialized with zeros to prevent null pointer lookups.
 */
public class SimulationStatistics {

    private final int totalEventsGenerated;
    private final int totalEventsProcessed;
    private final Map<AttackType, Integer> eventsByAttackType = new EnumMap<>(AttackType.class);
    private final Map<Severity, Integer> eventsBySeverity = new EnumMap<>(Severity.class);

    private final int totalAlerts;
    private final Map<Severity, Integer> alertsBySeverity = new EnumMap<>(Severity.class);

    private final Map<PredictionClass, Integer> predictionsByClass = new EnumMap<>(PredictionClass.class);
    private final Map<DefenseActionType, Integer> actionsByType = new EnumMap<>(DefenseActionType.class);
    private final Map<IncidentStatus, Integer> incidentsByStatus = new EnumMap<>(IncidentStatus.class);

    private final int totalDevices;
    private final int activeConnections;
    private final int blockedConnections;
    private final int disconnectedConnections;

    public SimulationStatistics(Collection<SecurityEvent> events,
                                Collection<SecurityAlert> alerts,
                                Collection<ThreatPrediction> predictions,
                                Collection<DefenseResult> actions,
                                Collection<SecurityIncident> incidents,
                                VirtualNetwork network,
                                NetworkTopology topology) {

        // 1. Event distributions
        this.totalEventsGenerated = (events != null) ? events.size() : 0;
        this.totalEventsProcessed = this.totalEventsGenerated;

        if (events != null) {
            for (SecurityEvent ev : events) {
                eventsByAttackType.merge(ev.getAttackType(), 1, Integer::sum);
                eventsBySeverity.merge(ev.getSeverity(), 1, Integer::sum);
            }
        }

        // 2. Alert distributions
        this.totalAlerts = (alerts != null) ? alerts.size() : 0;
        if (alerts != null) {
            for (SecurityAlert al : alerts) {
                alertsBySeverity.merge(al.getSeverity(), 1, Integer::sum);
            }
        }

        // 3. ML prediction distributions
        if (predictions != null) {
            for (ThreatPrediction p : predictions) {
                predictionsByClass.merge(p.getPredictedClass(), 1, Integer::sum);
            }
        }

        // 4. Defensive action distributions
        if (actions != null) {
            for (DefenseResult act : actions) {
                actionsByType.merge(act.getActionType(), 1, Integer::sum);
            }
        }

        // 5. Incident status distributions
        if (incidents != null) {
            for (SecurityIncident inc : incidents) {
                incidentsByStatus.merge(inc.getStatus(), 1, Integer::sum);
            }
        }

        // 6. Network state
        this.totalDevices = (network != null) ? network.getTotalDeviceCount() : 0;
        this.activeConnections = (topology != null) ? topology.getActiveConnectionCount() : 0;
        this.blockedConnections = (topology != null) ? topology.getBlockedConnectionCount() : 0;
        this.disconnectedConnections = (topology != null) ? topology.getDisconnectedConnectionCount() : 0;
    }

    // ---------------------------------------------------------------
    // Getters
    // ---------------------------------------------------------------

    public int getTotalEventsGenerated() { return totalEventsGenerated; }
    public int getTotalEventsProcessed() { return totalEventsProcessed; }
    public Map<AttackType, Integer> getEventsByAttackType() { return Collections.unmodifiableMap(eventsByAttackType); }
    public Map<Severity, Integer> getEventsBySeverity() { return Collections.unmodifiableMap(eventsBySeverity); }

    public int getTotalAlerts() { return totalAlerts; }
    public Map<Severity, Integer> getAlertsBySeverity() { return Collections.unmodifiableMap(alertsBySeverity); }

    public Map<PredictionClass, Integer> getPredictionsByClass() { return Collections.unmodifiableMap(predictionsByClass); }
    public Map<DefenseActionType, Integer> getActionsByType() { return Collections.unmodifiableMap(actionsByType); }
    public Map<IncidentStatus, Integer> getIncidentsByStatus() { return Collections.unmodifiableMap(incidentsByStatus); }

    public int getTotalDevices() { return totalDevices; }
    public int getActiveConnections() { return activeConnections; }
    public int getBlockedConnections() { return blockedConnections; }
    public int getDisconnectedConnections() { return disconnectedConnections; }
}
