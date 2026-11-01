package cybershield.monitoring;

import cybershield.model.NetworkNode;
import cybershield.model.Router;
import cybershield.model.Server;
import cybershield.network.VirtualNetwork;
import cybershield.security.SecurityEvent;
import cybershield.security.Severity;

import java.util.Optional;

/**
 * RiskScorer — CyberShield Arena Phase 4
 *
 * Scoring Formula & Rationale:
 *   The risk score is a deterministic, rule-based heuristic indicator from 0 to 100.
 *   NOTE: It is NOT a statistically calibrated probability of compromise.
 *
 * Components:
 *   1. Base Severity Weight (up to 70 pts):
 *        LOW = 25 pts, MEDIUM = 45 pts, HIGH = 65 pts, CRITICAL = 80 pts.
 *   2. Activity Volume Factor (up to 20 pts):
 *        Calculated from failed logins, connection frequency, and scanned ports:
 *        volumeBonus = Math.min(20, (failedLogins * 1.0) + (uniquePorts * 0.4) + (attempts * 0.5))
 *   3. Target Asset Criticality (up to 10 pts):
 *        If the target device is an enterprise Server or Gateway Router, +10 pts bonus.
 *
 *   Final Score = Math.max(0, Math.min(100, Math.round(base + volumeBonus + targetBonus)))
 */
public class RiskScorer {

    private final int lowBase;
    private final int mediumBase;
    private final int highBase;
    private final int criticalBase;
    private final int criticalAssetBonus;

    public RiskScorer() {
        this(25, 45, 65, 80, 10);
    }

    public RiskScorer(int lowBase, int mediumBase, int highBase, int criticalBase, int criticalAssetBonus) {
        this.lowBase = lowBase;
        this.mediumBase = mediumBase;
        this.highBase = highBase;
        this.criticalBase = criticalBase;
        this.criticalAssetBonus = criticalAssetBonus;
    }

    /**
     * Calculates risk score for an event and detection result without network context.
     */
    public int calculateScore(SecurityEvent event, DetectionResult result) {
        return calculateScore(event, result, null);
    }

    /**
     * Calculates risk score incorporating network asset importance.
     *
     * @param event   the triggering SecurityEvent
     * @param result  the matching DetectionResult
     * @param network optional VirtualNetwork to inspect target asset importance
     * @return risk score clamped strictly between 0 and 100
     */
    public int calculateScore(SecurityEvent event, DetectionResult result, VirtualNetwork network) {
        if (event == null || result == null) {
            return 0;
        }

        // 1. Base score from recommended severity
        Severity severity = result.getRecommendedSeverity();
        double base = switch (severity) {
            case LOW -> lowBase;
            case MEDIUM -> mediumBase;
            case HIGH -> highBase;
            case CRITICAL -> criticalBase;
        };

        // 2. Volume bonus (up to 20 points)
        double volumeBonus = (event.getFailedLoginCount() * 1.0)
                + (event.getUniquePortCount() * 0.4)
                + (event.getConnectionAttemptCount() * 0.5);
        volumeBonus = Math.min(20.0, volumeBonus);

        // 3. Target asset importance (up to 10 points)
        double targetBonus = 0.0;
        if (network != null) {
            Optional<NetworkNode> targetOpt = network.findDeviceById(event.getTargetNodeId());
            if (targetOpt.isPresent()) {
                NetworkNode node = targetOpt.get();
                if (node instanceof Server || node instanceof Router) {
                    targetBonus = criticalAssetBonus;
                }
            }
        }

        int total = (int) Math.round(base + volumeBonus + targetBonus);
        return Math.max(0, Math.min(100, total));
    }
}
