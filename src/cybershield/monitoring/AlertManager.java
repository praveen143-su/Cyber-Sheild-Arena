package cybershield.monitoring;

import cybershield.security.Severity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * AlertManager — CyberShield Arena Phase 4
 *
 * OOP Concepts demonstrated:
 *   - Encapsulation     : Private alert storage with unmodifiable views.
 *   - Deduplication     : Prevents duplicate alerts for identical (eventId, ruleId) pairs.
 *   - Separation of Concerns: Keeps alert handling completely separate from raw event logging.
 */
public class AlertManager {

    private final Map<String, SecurityAlert> alertsById = new LinkedHashMap<>();
    private final Set<String> eventRuleDeduplicationSet = new HashSet<>();

    public AlertManager() {
        // Default constructor
    }

    /**
     * Attempts to record an alert.
     * Prevents duplicate alerts for the same (eventId, ruleId) combination.
     *
     * @param alert the SecurityAlert to add
     * @return true if added, false if rejected as a duplicate
     */
    public boolean addAlert(SecurityAlert alert) {
        if (alert == null) {
            return false;
        }

        // Deduplication key: eventId + "::" + ruleId(s)
        String dedupKey = alert.getEventId() + "::" + String.join(",", alert.getAssociatedRuleIds());
        if (eventRuleDeduplicationSet.contains(dedupKey)) {
            System.out.printf("[AlertManager] Duplicate alert suppressed: Event %s already triggered rule(s) %s\n",
                    alert.getEventId(), alert.getAssociatedRuleIds());
            return false;
        }

        eventRuleDeduplicationSet.add(dedupKey);
        alertsById.put(alert.getAlertId(), alert);
        return true;
    }

    public List<SecurityAlert> getAllAlerts() {
        return Collections.unmodifiableList(new ArrayList<>(alertsById.values()));
    }

    public List<SecurityAlert> getAlertsBySeverity(Severity severity) {
        List<SecurityAlert> filtered = new ArrayList<>();
        for (SecurityAlert alert : alertsById.values()) {
            if (alert.getSeverity() == severity) {
                filtered.add(alert);
            }
        }
        return Collections.unmodifiableList(filtered);
    }

    public int getTotalAlertCount() {
        return alertsById.size();
    }

    public int getAlertCountBySeverity(Severity severity) {
        int count = 0;
        for (SecurityAlert alert : alertsById.values()) {
            if (alert.getSeverity() == severity) {
                count++;
            }
        }
        return count;
    }

    /**
     * Renders a clean formatted table of all active security alerts.
     */
    public void displayAlertSummary() {
        System.out.println("\n+--------------------------------------------------------------------------------------------------------------------+");
        System.out.printf("| %-114s |\n", "ACTIVE SECURITY ALERTS (" + getTotalAlertCount() + " Alerts Raised)");
        System.out.println("+----------+----------+----------+----------+----------+-------+-----------------------------------------------------+");
        System.out.printf("| %-8s | %-8s | %-8s | %-8s | %-8s | %-5s | %-51s |\n",
                "Alert ID", "Event ID", "Source", "Target", "Severity", "Score", "Alert Title & Explanation");
        System.out.println("+----------+----------+----------+----------+----------+-------+-----------------------------------------------------+");

        for (SecurityAlert alert : alertsById.values()) {
            String titleAndDesc = alert.getAlertTitle() + " (" + alert.getExplanation() + ")";
            if (titleAndDesc.length() > 51) {
                titleAndDesc = titleAndDesc.substring(0, 48) + "...";
            }
            System.out.printf("| %-8s | %-8s | %-8s | %-8s | %-8s | %-5s | %-51s |\n",
                    alert.getAlertId(),
                    alert.getEventId(),
                    alert.getSourceNodeId(),
                    alert.getTargetNodeId(),
                    alert.getSeverity(),
                    alert.getRiskScore() + "/100",
                    titleAndDesc);
        }

        System.out.println("+----------+----------+----------+----------+----------+-------+-----------------------------------------------------+");
        System.out.printf("  Alerts Breakdown: CRITICAL=%d | HIGH=%d | MEDIUM=%d | LOW=%d\n\n",
                getAlertCountBySeverity(Severity.CRITICAL),
                getAlertCountBySeverity(Severity.HIGH),
                getAlertCountBySeverity(Severity.MEDIUM),
                getAlertCountBySeverity(Severity.LOW));
    }
}
