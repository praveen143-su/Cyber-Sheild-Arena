package cybershield.defense;

import cybershield.monitoring.SecurityAlert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * IncidentResponseManager — CyberShield Arena Phase 6
 *
 * OOP Concepts demonstrated:
 *   - Encapsulation         : Manages incident lifecycle registries privately.
 *   - Information Hiding    : Exposes unmodifiable collection views.
 *   - Defensive Programming : Validates inputs and maintains referential integrity between alerts & incidents.
 */
public class IncidentResponseManager {

    private final Map<String, SecurityIncident> incidentsById = new LinkedHashMap<>();
    private final Map<String, String> alertToIncidentMap = new LinkedHashMap<>();

    public IncidentResponseManager() {
        // Default constructor
    }

    /**
     * Creates and registers a new SecurityIncident from a SecurityAlert.
     * If an open incident already exists for the alert's source/target pair, correlates it.
     */
    public synchronized SecurityIncident createOrUpdateIncident(SecurityAlert alert) {
        if (alert == null) {
            throw new IllegalArgumentException("Cannot create incident for null alert.");
        }

        // Check if an incident is already associated with this alert
        if (alertToIncidentMap.containsKey(alert.getAlertId())) {
            return incidentsById.get(alertToIncidentMap.get(alert.getAlertId()));
        }

        // Check for an existing OPEN or INVESTIGATING incident on the same target device
        for (SecurityIncident existing : incidentsById.values()) {
            if ((existing.getStatus() == IncidentStatus.OPEN || existing.getStatus() == IncidentStatus.INVESTIGATING) &&
                existing.getTargetNodeId().equalsIgnoreCase(alert.getTargetNodeId())) {
                existing.associateAlert(alert.getAlertId());
                existing.addAuditNote("Correlated Alert " + alert.getAlertId() + " (" + alert.getAlertTitle() + ") to active incident");
                alertToIncidentMap.put(alert.getAlertId(), existing.getIncidentId());
                return existing;
            }
        }

        SecurityIncident newIncident = new SecurityIncident(alert);
        incidentsById.put(newIncident.getIncidentId(), newIncident);
        alertToIncidentMap.put(alert.getAlertId(), newIncident.getIncidentId());
        return newIncident;
    }

    public synchronized Optional<SecurityIncident> findIncidentById(String incidentId) {
        if (incidentId == null) return Optional.empty();
        return Optional.ofNullable(incidentsById.get(incidentId.trim()));
    }

    public synchronized Optional<SecurityIncident> findIncidentByAlertId(String alertId) {
        if (alertId == null) return Optional.empty();
        String incId = alertToIncidentMap.get(alertId.trim());
        if (incId == null) return Optional.empty();
        return Optional.ofNullable(incidentsById.get(incId));
    }

    public synchronized List<SecurityIncident> getAllIncidents() {
        return Collections.unmodifiableList(new ArrayList<>(incidentsById.values()));
    }

    public synchronized List<SecurityIncident> getOpenIncidents() {
        List<SecurityIncident> open = new ArrayList<>();
        for (SecurityIncident inc : incidentsById.values()) {
            if (inc.getStatus() != IncidentStatus.CLOSED) {
                open.add(inc);
            }
        }
        return Collections.unmodifiableList(open);
    }

    public synchronized List<SecurityIncident> getResolvedIncidents() {
        List<SecurityIncident> resolved = new ArrayList<>();
        for (SecurityIncident inc : incidentsById.values()) {
            if (inc.getStatus() == IncidentStatus.CLOSED || inc.getStatus() == IncidentStatus.RECOVERED) {
                resolved.add(inc);
            }
        }
        return Collections.unmodifiableList(resolved);
    }

    public synchronized int getTotalIncidentCount() {
        return incidentsById.size();
    }

    public synchronized void displayIncidentSummary() {
        System.out.println("\n+----------------------------------------------------------------------------------------------------+");
        System.out.printf("| %-98s |\n", "INCIDENT RESPONSE LOG (" + getTotalIncidentCount() + " Total Incidents Tracked)");
        System.out.println("+----------+---------------+----------+----------+----------------------+----------------------------+");
        System.out.printf("| %-8s | %-13s | %-8s | %-8s | %-20s | %-26s |\n",
                "Inc ID", "Status", "Source", "Target", "Primary Alert", "Created At");
        System.out.println("+----------+---------------+----------+----------+----------------------+----------------------------+");

        for (SecurityIncident inc : incidentsById.values()) {
            System.out.printf("| %-8s | %-13s | %-8s | %-8s | %-20s | %-26s |\n",
                    inc.getIncidentId(),
                    inc.getStatus().name(),
                    inc.getSourceNodeId(),
                    inc.getTargetNodeId(),
                    inc.getPrimaryAlertId(),
                    inc.getCreatedAt().toString().substring(0, 19));
        }

        System.out.println("+----------+---------------+----------+----------+----------------------+----------------------------+");
        System.out.printf("  Active Incidents: %d | Resolved / Recovered: %d\n\n",
                getOpenIncidents().size(), getResolvedIncidents().size());
    }
}
