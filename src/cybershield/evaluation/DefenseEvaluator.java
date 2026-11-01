package cybershield.evaluation;

import cybershield.defense.DefenseResult;
import cybershield.defense.IncidentStatus;
import cybershield.defense.SecurityIncident;

import java.util.Collection;

/**
 * DefenseEvaluator — CyberShield Arena Phase 7
 *
 * OOP Concepts demonstrated:
 *   - Encapsulation         : Exposes immutable evaluated metrics.
 *   - Domain Discrimination : Strictly distinguishes individual API action success from
 *                             incident-level closed-loop containment and recovery.
 *   - Empirical Integrity   : Calculates actual statistics from Phase 6 DefenseResults and incidents.
 */
public class DefenseEvaluator {

    private final int totalAttemptedActions;
    private final int successfulActions;
    private final int failedOrRejectedActions;
    private final int duplicateActionsPrevented;

    private final int totalIncidents;
    private final int incidentsContained;
    private final int incidentsRecovered;
    private final int incidentsOpen;
    private final double containmentRate;
    private final double recoveryRate;

    /**
     * Evaluates defensive action logs and incident records.
     *
     * @param actions   collection of DefenseResult records executed in Phase 6
     * @param incidents collection of SecurityIncident instances from IncidentResponseManager
     */
    public DefenseEvaluator(Collection<DefenseResult> actions, Collection<SecurityIncident> incidents) {
        int attempted = 0;
        int success = 0;
        int failed = 0;
        int duplicates = 0;

        if (actions != null) {
            for (DefenseResult res : actions) {
                attempted++;
                if (res.isSuccess()) {
                    success++;
                } else {
                    failed++;
                }

                String desc = res.getResultDescription();
                String reason = res.getFailureReason();
                if ((desc != null && desc.toLowerCase().contains("duplicate")) ||
                    (reason != null && reason.toLowerCase().contains("duplicate"))) {
                    duplicates++;
                }
            }
        }

        this.totalAttemptedActions = attempted;
        this.successfulActions = success;
        this.failedOrRejectedActions = failed;
        this.duplicateActionsPrevented = duplicates;

        int totalInc = 0;
        int contained = 0;
        int recovered = 0;
        int open = 0;

        if (incidents != null) {
            for (SecurityIncident inc : incidents) {
                totalInc++;
                IncidentStatus st = inc.getStatus();
                if (st == IncidentStatus.CONTAINED || st == IncidentStatus.RECOVERED || st == IncidentStatus.CLOSED) {
                    contained++;
                }
                if (st == IncidentStatus.RECOVERED || st == IncidentStatus.CLOSED) {
                    recovered++;
                }
                if (st == IncidentStatus.OPEN || st == IncidentStatus.INVESTIGATING) {
                    open++;
                }
            }
        }

        this.totalIncidents = totalInc;
        this.incidentsContained = contained;
        this.incidentsRecovered = recovered;
        this.incidentsOpen = open;

        this.containmentRate = (totalInc == 0) ? 0.0 : (double) contained / totalInc;
        this.recoveryRate = (contained == 0) ? 0.0 : (double) recovered / contained;
    }

    // ---------------------------------------------------------------
    // Getters
    // ---------------------------------------------------------------

    public int getTotalAttemptedActions() { return totalAttemptedActions; }
    public int getSuccessfulActions() { return successfulActions; }
    public int getFailedOrRejectedActions() { return failedOrRejectedActions; }
    public int getDuplicateActionsPrevented() { return duplicateActionsPrevented; }

    public int getTotalIncidents() { return totalIncidents; }
    public int getIncidentsContained() { return incidentsContained; }
    public int getIncidentsRecovered() { return incidentsRecovered; }
    public int getIncidentsOpen() { return incidentsOpen; }

    public double getContainmentRate() { return containmentRate; }
    public double getRecoveryRate() { return recoveryRate; }

    @Override
    public String toString() {
        return String.format(
                "Defense Effectiveness: Actions [Attempted=%d, Success=%d, Failed=%d, Dups=%d] | " +
                "Incidents [Total=%d, Contained=%d (%.1f%%), Recovered=%d (%.1f%%), Open=%d]",
                totalAttemptedActions, successfulActions, failedOrRejectedActions, duplicateActionsPrevented,
                totalIncidents, incidentsContained, containmentRate * 100,
                incidentsRecovered, recoveryRate * 100, incidentsOpen
        );
    }
}
