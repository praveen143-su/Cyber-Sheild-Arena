package cybershield.arena;

/**
 * SimulationScenario — Defines pre-configured cyber attack scenarios for the Arena.
 *
 * Scenarios allow students and evaluators to trigger multi-stage, realistic
 * cybersecurity attack sequences with a single command.
 */
public enum SimulationScenario {

    /**
     * Targeted Reconnaissance & Brute-Force:
     * Port scan across servers followed by SSH credential brute force.
     */
    RECON_AND_BRUTE_FORCE(
            "Reconnaissance & Credential Attack",
            "Scans Web/DB server ports, then launches an intensive SSH brute-force credential attack."
    ),

    /**
     * Data Exfiltration Anomaly:
     * High-volume anomalous connection burst representing covert data exfiltration.
     */
    DATA_EXFILTRATION_ANOMALY(
            "Covert Data Exfiltration",
            "Simulates rapid burst connections to extract sensitive database assets."
    ),

    /**
     * Advanced Persistent Threat (APT):
     * Multi-stage campaign: Perimeter scan -> Gateway probe -> MySQL Root exploit.
     */
    ADVANCED_PERSISTENT_THREAT(
            "Multi-Stage APT Campaign",
            "Complex kill-chain attacking perimeter router, web app, and database core."
    ),

    /**
     * Benign Network Baseline:
     * Low-volume legitimate user connections to evaluate false-positive suppression.
     */
    BENIGN_TRAFFIC_BASELINE(
            "Benign Traffic Baseline",
            "Normal authorized workstation access to verify defense stability and zero false blocks."
    );

    private final String title;
    private final String description;

    SimulationScenario(String title, String description) {
        this.title = title;
        this.description = description;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s", title, description);
    }
}
