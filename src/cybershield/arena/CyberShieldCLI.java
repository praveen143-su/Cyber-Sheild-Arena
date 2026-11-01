package cybershield.arena;

import cybershield.defense.DefenseResult;
import cybershield.defense.SecurityIncident;
import cybershield.evaluation.EvaluationMetrics;
import cybershield.ml.ThreatPrediction;
import cybershield.monitoring.SecurityAlert;
import cybershield.security.SecurityEvent;

import java.io.InputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

/**
 * CyberShieldCLI — Interactive Command-Line Console & Simulation Dashboard for CyberShield Arena.
 *
 * Provides a user-friendly, menu-driven interface enabling operators to:
 *   1. Monitor live network topology and device health
 *   2. Launch custom simulated cyber attacks (Port Scan, Login Brute-Force, Traffic Anomaly)
 *   3. Run realistic multi-phase cyber warfare scenarios (APT, Reconnaissance, Data Exfiltration)
 *   4. Inspect SOC alerts, event queues, and risk scores
 *   5. Inspect ML Decision Tree predictions and confidence gauges
 *   6. Trigger automated incident response and containment
 *   7. Inspect defense audit logs and incident lifecycles
 *   8. Generate and export comprehensive evaluation reports (TXT & CSV)
 *   9. Execute one-click automated demonstration mode
 *  10. Run system verification test suites
 */
public class CyberShieldCLI {

    private final ArenaController controller;
    private final Scanner scanner;
    private final PrintStream out;
    private boolean running = true;

    public CyberShieldCLI() {
        this(System.in, System.out);
    }

    public CyberShieldCLI(InputStream in, PrintStream out) {
        this.controller = new ArenaController();
        this.scanner = new Scanner(in);
        this.out = out;
    }

    public ArenaController getController() {
        return controller;
    }

    /**
     * Starts the interactive command-line loop.
     */
    public void start() {
        ArenaDashboard.displayBanner();
        out.println("  Welcome to the CyberShield Arena Interactive Simulation Terminal.");
        out.println("  Type the number corresponding to your chosen operation.\n");

        while (running) {
            printMainMenu();
            out.print("  Select an option [0-11]: ");

            if (!scanner.hasNextLine()) {
                // End of input stream (e.g. redirected input)
                break;
            }

            String input = scanner.nextLine().trim();
            handleMenuSelection(input);
        }

        out.println("\n  [EXIT] Thank you for using CyberShield Arena. Goodbye!");
    }

    private void printMainMenu() {
        out.println("\n" + ArenaDashboard.ANSI_BOLD + "=============================== MASTER ARENA MENU ===============================" + ArenaDashboard.ANSI_RESET);
        out.println("  [1]  View Virtual Network Topology & Device Health");
        out.println("  [2]  Launch Interactive Simulated Attack (Port Scan / Brute-Force / Anomaly)");
        out.println("  [3]  Execute Pre-Configured Attack Scenarios (APT, Recon, Exfiltration, Benign)");
        out.println("  [4]  Inspect SOC Alerts, Event Queues & Risk Scoring Feed");
        out.println("  [5]  Machine Learning Intelligence Center (Decision Tree Predictions)");
        out.println("  [6]  Trigger End-to-End Automated Defense & Incident Containment Cycle");
        out.println("  [7]  View Incident Registry & Defense Audit Log (logs/defense-audit.csv)");
        out.println("  [8]  Generate & Export Evaluation Reports (reports/*.txt & reports/*.csv)");
        out.println("  [9]  Execute One-Click Automated Cyber Warfare Battle (Demo Mode)");
        out.println("  [10] Run Comprehensive Multi-Phase System Verification Tests");
        out.println("  [11] Reset Network & Simulation to Baseline");
        out.println("  [0]  Exit CyberShield Arena");
        out.println("=================================================================================");
    }

    private void handleMenuSelection(String input) {
        switch (input) {
            case "1":
                ArenaDashboard.displayNetworkTopology(controller.getVirtualNetwork(), controller.getNetworkTopology());
                break;
            case "2":
                handleInteractiveAttack();
                break;
            case "3":
                handleScenarioExecution();
                break;
            case "4":
                ArenaDashboard.displaySOCStatus(controller.getSecurityMonitor(), controller.getDefenseCoordinator().getIncidentManager());
                break;
            case "5":
                ArenaDashboard.displayMLPredictions(controller.getLatestPredictions());
                break;
            case "6":
                handleAutomatedDefenseCycle();
                break;
            case "7":
                ArenaDashboard.displayIncidentRegistry(
                        controller.getDefenseCoordinator().getIncidentManager(),
                        controller.getDefenseCoordinator().getAuditLogger()
                );
                break;
            case "8":
                handleReportGeneration();
                break;
            case "9":
                handleOneClickBattleDemo();
                break;
            case "10":
                handleRunVerificationTests();
                break;
            case "11":
                controller.resetSimulation();
                out.println(ArenaDashboard.ANSI_GREEN + "\n  [OK] Simulation state, devices, and incident registries reset to baseline." + ArenaDashboard.ANSI_RESET);
                break;
            case "0":
            case "exit":
            case "quit":
                running = false;
                break;
            default:
                out.println(ArenaDashboard.ANSI_YELLOW + "  [!] Invalid choice. Please enter a number between 0 and 11." + ArenaDashboard.ANSI_RESET);
                break;
        }
    }

    private void handleInteractiveAttack() {
        ArenaDashboard.displayHeader("LAUNCH CUSTOM SIMULATED ATTACK");
        out.println("  Choose attack vector:");
        out.println("    [1] Port Sweep Reconnaissance (Probing port ranges)");
        out.println("    [2] Credential Brute-Force Attack (Repeated auth failures)");
        out.println("    [3] Anomalous Traffic Burst (High packet rate / exfiltration)");
        out.print("  Select attack type [1-3]: ");

        String choice = scanner.nextLine().trim();
        out.print("  Attacker Source Device ID [default: WS-001]: ");
        String src = scanner.nextLine().trim();
        if (src.isEmpty()) src = "WS-001";

        out.print("  Target Victim Device ID [default: SRV-001]: ");
        String tgt = scanner.nextLine().trim();
        if (tgt.isEmpty()) tgt = "SRV-001";

        List<SecurityEvent> events;
        switch (choice) {
            case "1":
                out.print("  Number of ports to sweep [default: 12]: ");
                String pStr = scanner.nextLine().trim();
                int portCount = pStr.isEmpty() ? 12 : Integer.parseInt(pStr);
                events = controller.launchPortScan(src, tgt, Arrays.asList(21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080, 8443));
                out.printf(ArenaDashboard.ANSI_GREEN + "  [ATTACK EXECUTED] Dispatched Port Sweep across %d ports. Ingested %d events.%n" + ArenaDashboard.ANSI_RESET,
                        portCount, events.size());
                break;
            case "2":
                out.print("  Username target [default: admin]: ");
                String user = scanner.nextLine().trim();
                if (user.isEmpty()) user = "admin";
                out.print("  Number of failed login attempts [default: 15]: ");
                String aStr = scanner.nextLine().trim();
                int attempts = aStr.isEmpty() ? 15 : Integer.parseInt(aStr);
                events = controller.launchBruteForce(src, tgt, user, attempts);
                out.printf(ArenaDashboard.ANSI_GREEN + "  [ATTACK EXECUTED] Dispatched Brute-Force against user '%s' (%d attempts). Ingested %d events.%n" + ArenaDashboard.ANSI_RESET,
                        user, attempts, events.size());
                break;
            case "3":
                out.print("  Destination Port [default: 3306]: ");
                String dPortStr = scanner.nextLine().trim();
                int dPort = dPortStr.isEmpty() ? 3306 : Integer.parseInt(dPortStr);
                out.print("  Packet Count burst [default: 200]: ");
                String pBurstStr = scanner.nextLine().trim();
                int pBurst = pBurstStr.isEmpty() ? 200 : Integer.parseInt(pBurstStr);
                events = controller.launchSuspiciousConnection(src, tgt, dPort, pBurst, 0.05);
                out.printf(ArenaDashboard.ANSI_GREEN + "  [ATTACK EXECUTED] Dispatched Traffic Burst to port %d (%d packets). Ingested %d events.%n" + ArenaDashboard.ANSI_RESET,
                        dPort, pBurst, events.size());
                break;
            default:
                out.println(ArenaDashboard.ANSI_YELLOW + "  [!] Unknown attack type. Operation cancelled." + ArenaDashboard.ANSI_RESET);
                break;
        }
    }

    private void handleScenarioExecution() {
        ArenaDashboard.displayHeader("SELECT & EXECUTE CYBER WARFARE SCENARIO");
        SimulationScenario[] scenarios = SimulationScenario.values();
        for (int i = 0; i < scenarios.length; i++) {
            out.printf("  [%d] %-30s - %s%n", i + 1, scenarios[i].getTitle(), scenarios[i].getDescription());
        }
        out.print("  Select scenario [1-" + scenarios.length + "]: ");

        try {
            int idx = Integer.parseInt(scanner.nextLine().trim()) - 1;
            if (idx >= 0 && idx < scenarios.length) {
                SimulationScenario selected = scenarios[idx];
                out.printf("\n  Executing Scenario '%s'...%n", selected.getTitle());
                List<SecurityEvent> events = controller.executeScenario(selected);
                out.printf(ArenaDashboard.ANSI_GREEN + "  [OK] Scenario completed successfully! Generated and ingested %d security events.%n" + ArenaDashboard.ANSI_RESET,
                        events.size());
            } else {
                out.println(ArenaDashboard.ANSI_YELLOW + "  [!] Invalid scenario selection." + ArenaDashboard.ANSI_RESET);
            }
        } catch (Exception e) {
            out.println(ArenaDashboard.ANSI_RED + "  [!] Error parsing input: " + e.getMessage() + ArenaDashboard.ANSI_RESET);
        }
    }

    private void handleAutomatedDefenseCycle() {
        ArenaDashboard.displayHeader("EXECUTING AUTOMATED INCIDENT RESPONSE PIPELINE");
        out.println("  1. Ingesting and processing event queue through detection rules...");
        out.println("  2. Calculating risk scores and correlating security alerts...");
        out.println("  3. Running Machine Learning inference on event features...");
        out.println("  4. Evaluating DefensePolicy matrix against Risk Score & ML Confidence...");
        out.println("  5. Executing automated counter-measures (Block, Isolate, Temp-Block)...");

        List<DefenseResult> results = controller.runEndToEndDefenseCycle();

        out.printf("\n" + ArenaDashboard.ANSI_GREEN + "  [CYCLE COMPLETE] Evaluated %d defense responses across active alerts.%n" + ArenaDashboard.ANSI_RESET,
                results.size());

        for (DefenseResult res : results) {
            String color = res.isSuccess() ? ArenaDashboard.ANSI_GREEN : ArenaDashboard.ANSI_YELLOW;
            out.printf("   * %s[%s]%s Action: %-18s | Target: %-15s | %s%n",
                    color, (res.isSuccess() ? "SUCCESS" : "REJECTED"), ArenaDashboard.ANSI_RESET,
                    res.getActionType().name(),
                    res.getTargetId(),
                    res.getResultDescription()
            );
        }

        // Show updated active incidents
        List<SecurityIncident> activeIncidents = controller.getDefenseCoordinator().getIncidentManager().getAllIncidents();
        out.printf("\n  Current Incident Count: %d registered incidents in response manager.%n", activeIncidents.size());
    }

    private void handleReportGeneration() {
        ArenaDashboard.displayHeader("GENERATE & EXPORT COMPREHENSIVE EVALUATION REPORT");
        out.print("  Enter simulation session title [default: CyberShield Arena Live Session]: ");
        String title = scanner.nextLine().trim();
        if (title.isEmpty()) {
            title = "CyberShield Arena Live Session";
        }

        out.println("  Synthesizing performance telemetry, confusion matrices, and audit logs...");
        String reportId = controller.generateEvaluationReport(title);

        out.println(ArenaDashboard.ANSI_GREEN + "\n  [REPORTS EXPORTED SUCCESSFULLY]" + ArenaDashboard.ANSI_RESET);
        out.printf("  * Text Analysis Report : reports/simulation-report-%s.txt%n", reportId);
        out.printf("  * CSV Evaluation Export : reports/evaluation-metrics-%s.csv%n", reportId);

        // Display on-screen summary
        controller.getEvaluationCoordinator().displayEvaluationDashboard();
    }

    private void handleOneClickBattleDemo() {
        ArenaDashboard.displayHeader("ONE-CLICK FULL CYBER WARFARE BATTLE SIMULATION (PHASES 1-7)");
        out.println("  [STEP 1] Resetting network to pristine operational state...");
        controller.resetSimulation();

        out.println("  [STEP 2] Launching Multi-Stage APT Campaign (Reconnaissance + Exploit)...");
        controller.executeScenario(SimulationScenario.ADVANCED_PERSISTENT_THREAT);

        out.println("  [STEP 3] Running End-to-End SOC Detection & Automated Incident Response...");
        List<DefenseResult> defenseResults = controller.runEndToEndDefenseCycle();

        out.println("  [STEP 4] Generating Full Benchmark Evaluation & Incident Audit Reports...");
        String reportId = controller.generateEvaluationReport("Automated Battle Demonstration");

        out.println("\n" + ArenaDashboard.ANSI_CYAN + ANSI_BOLD + "====================== BATTLE RESULTS DASHBOARD ======================" + ArenaDashboard.ANSI_RESET);
        ArenaDashboard.displayNetworkTopology(controller.getVirtualNetwork(), controller.getNetworkTopology());
        ArenaDashboard.displaySOCStatus(controller.getSecurityMonitor(), controller.getDefenseCoordinator().getIncidentManager());
        ArenaDashboard.displayMLPredictions(controller.getLatestPredictions());
        ArenaDashboard.displayIncidentRegistry(controller.getDefenseCoordinator().getIncidentManager(), controller.getDefenseCoordinator().getAuditLogger());

        out.println(ArenaDashboard.ANSI_GREEN + ANSI_BOLD + "\n>>> BATTLE COMPLETE: Threats contained and audited successfully in " + reportId + "!" + ArenaDashboard.ANSI_RESET);
    }

    private void handleRunVerificationTests() {
        ArenaDashboard.displayHeader("MULTI-PHASE COMPREHENSIVE SYSTEM VERIFICATION TESTS");
        ArenaTestSuite suite = new ArenaTestSuite();
        suite.runAllTests(controller);
    }

    private static final String ANSI_BOLD = ArenaDashboard.ANSI_BOLD;

    public static void main(String[] args) {
        CyberShieldCLI cli = new CyberShieldCLI();
        cli.start();
    }
}
