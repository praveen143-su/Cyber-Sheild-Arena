package cybershield.arena;

import cybershield.defense.BlockConnectionStrategy;
import cybershield.defense.DefenseActionType;
import cybershield.defense.DefenseAgent;
import cybershield.defense.DefenseAuditLogger;
import cybershield.defense.DefenseContext;
import cybershield.defense.DefenseCoordinator;
import cybershield.defense.DefensePolicy;
import cybershield.defense.DefenseResult;
import cybershield.defense.IncidentResponseManager;
import cybershield.defense.IsolateDeviceStrategy;
import cybershield.defense.RestoreDeviceStrategy;
import cybershield.defense.TemporaryBlockStrategy;
import cybershield.evaluation.EvaluationCoordinator;
import cybershield.evaluation.SimulationPerformanceEvaluator;
import cybershield.ml.MLDetectionEngine;
import cybershield.ml.ModelManager;
import cybershield.ml.ThreatPrediction;
import cybershield.ml.TrainingDataManager;
import cybershield.model.DeviceStatus;
import cybershield.model.NetworkNode;
import cybershield.model.Router;
import cybershield.model.Server;
import cybershield.model.Workstation;
import cybershield.monitoring.AlertManager;
import cybershield.monitoring.BruteForceDetectionRule;
import cybershield.monitoring.DetectionRule;
import cybershield.monitoring.EventLogger;
import cybershield.monitoring.EventProcessor;
import cybershield.monitoring.PortScanDetectionRule;
import cybershield.monitoring.RiskScorer;
import cybershield.monitoring.RuleBasedDetectionEngine;
import cybershield.monitoring.SecurityAlert;
import cybershield.monitoring.SecurityMonitor;
import cybershield.monitoring.SuspiciousConnectionRule;
import cybershield.network.NetworkTopology;
import cybershield.network.VirtualNetwork;
import cybershield.security.FirewallAction;
import cybershield.security.FirewallRule;
import cybershield.security.LoginAttackAction;
import cybershield.security.PortScanAction;
import cybershield.security.SecurityEvent;
import cybershield.security.SuspiciousConnectionAction;
import cybershield.simulation.SimulationEngine;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * ArenaController — Master domain controller and lifecycle orchestrator for CyberShield Arena.
 *
 * Integrates:
 *   - Phase 1 & 2: Virtual Network, Devices, Firewall Rules
 *   - Phase 3: Attack Simulation Engine & Attack Actions
 *   - Phase 4: Event Logging, Queued Processing, Rule Detection, Risk Scoring, Alerts
 *   - Phase 5: Weka J48 Decision Tree Inference Engine
 *   - Phase 6: Automated Defense Strategies, Policy Matrix & Incident Management
 *   - Phase 7: Benchmarking, Statistics, and Report Generation
 */
public class ArenaController {

    private final VirtualNetwork vnet;
    private final NetworkTopology topology;
    private SimulationEngine simEngine;
    private SecurityMonitor monitor;
    private MLDetectionEngine mlEngine;
    private weka.core.Instances testInstances;
    private DefenseCoordinator defenseCoordinator;
    private EvaluationCoordinator evalCoordinator;

    private final List<SecurityEvent> allSimulatedEvents = new ArrayList<>();
    private final List<ThreatPrediction> latestPredictions = new ArrayList<>();

    public ArenaController() {
        this.vnet = new VirtualNetwork();
        this.topology = new NetworkTopology(vnet);
        initializeNetwork();
        initializeMonitoring();
        initializeMachineLearning();
        initializeDefense();
        initializeEvaluation();
    }

    /**
     * Configures baseline virtual devices and initial perimeter firewall rules.
     */
    private void initializeNetwork() {
        Server appServer     = new Server("SRV-001", "Web App Server", "192.168.1.10", "HTTP", 8080);
        Server dbServer      = new Server("SRV-002", "Database Server", "192.168.1.11", "MySQL", 3306);
        Workstation studentWs = new Workstation("WS-001", "Student Workstation", "192.168.1.20", "Windows 11", "student");
        Workstation adminWs   = new Workstation("WS-002", "Admin Workstation", "192.168.1.21", "Ubuntu 22.04", "admin");
        Router coreRouter     = new Router("RTR-001", "Core Gateway Router", "192.168.1.1", true);

        vnet.registerDevice(appServer);
        vnet.registerDevice(dbServer);
        vnet.registerDevice(studentWs);
        vnet.registerDevice(adminWs);
        vnet.registerDevice(coreRouter);

        appServer.activate();
        dbServer.activate();
        studentWs.activate();
        adminWs.activate();
        coreRouter.activate();

        // Baseline firewall policies
        topology.addFirewallRule(new FirewallRule("FW-001", "WS-001", "SRV-001", FirewallAction.ALLOW));
        topology.addFirewallRule(new FirewallRule("FW-002", "WS-001", "SRV-002", FirewallAction.BLOCK));
        topology.addFirewallRule(new FirewallRule("FW-003", "WS-002", "SRV-002", FirewallAction.ALLOW));

        this.simEngine = new SimulationEngine(vnet, topology, "RedTeam-Adversary");
    }

    /**
     * Initializes Phase 4 Event Processing, Rule-Based Engine and SecurityMonitor.
     */
    private void initializeMonitoring() {
        EventLogger logger = new EventLogger("logs/security-events.csv");
        this.monitor = new SecurityMonitor(vnet, logger);
    }

    /**
     * Loads or trains the Phase 5 Weka Decision Tree model.
     */
    private void initializeMachineLearning() {
        try {
            TrainingDataManager dataManager = new TrainingDataManager();
            dataManager.loadFromCsv("data/training_data.csv");
            dataManager.splitTrainTest(0.80);
            this.testInstances = dataManager.getTestInstances();

            ModelManager modelManager = new ModelManager();
            if (!modelManager.tryLoadModel("models/cybershield_dt.model")) {
                modelManager.initializeAndTrain(dataManager.getTrainingInstances());
                modelManager.saveModel("models/cybershield_dt.model");
            }
            this.mlEngine = new MLDetectionEngine(modelManager.getModel());
        } catch (Exception e) {
            System.err.println("[ARENA ML INIT WARN] " + e.getMessage() + ". Initializing fallback detector.");
            this.mlEngine = null;
        }
    }

    /**
     * Initializes Phase 6 Automated Defense Subsystem and Incident Registry.
     */
    private void initializeDefense() {
        DefenseContext context = new DefenseContext(vnet, topology);
        DefensePolicy policy = new DefensePolicy();
        DefenseAgent agent = new DefenseAgent(context, policy);
        IncidentResponseManager incidentManager = new IncidentResponseManager();
        DefenseAuditLogger auditLogger = new DefenseAuditLogger("logs/defense-audit.csv");

        this.defenseCoordinator = new DefenseCoordinator(agent, incidentManager, auditLogger);
    }

    /**
     * Initializes Phase 7 Evaluation & Report Subsystem.
     */
    private void initializeEvaluation() {
        this.evalCoordinator = new EvaluationCoordinator();
    }

    // ============================================================
    // ATTACK SIMULATION METHODS (PHASE 3)
    // ============================================================

    public List<SecurityEvent> launchPortScan(String source, String target, List<Integer> ports) {
        long start = System.nanoTime();
        PortScanAction action = new PortScanAction("Targeted Port Sweep", source, target, ports);
        List<SecurityEvent> events = simEngine.runAttack(action);
        allSimulatedEvents.addAll(events);
        monitor.ingestEvents(events);
        evalCoordinator.getPerformanceEvaluator().recordRuleDetectionTime(System.nanoTime() - start);
        return events;
    }

    public List<SecurityEvent> launchBruteForce(String source, String target, String username, int attempts) {
        long start = System.nanoTime();
        LoginAttackAction action = new LoginAttackAction("Brute-Force Credential Attack", source, target, username, attempts);
        List<SecurityEvent> events = simEngine.runAttack(action);
        allSimulatedEvents.addAll(events);
        monitor.ingestEvents(events);
        evalCoordinator.getPerformanceEvaluator().recordRuleDetectionTime(System.nanoTime() - start);
        return events;
    }

    public List<SecurityEvent> launchSuspiciousConnection(String source, String target, int port, int packetCount, double intervalMs) {
        long start = System.nanoTime();
        SuspiciousConnectionAction action = new SuspiciousConnectionAction("Suspicious Connection Burst", source, target, packetCount);
        List<SecurityEvent> events = simEngine.runAttack(action);
        allSimulatedEvents.addAll(events);
        monitor.ingestEvents(events);
        evalCoordinator.getPerformanceEvaluator().recordRuleDetectionTime(System.nanoTime() - start);
        return events;
    }

    /**
     * Executes a pre-configured multi-step cyber scenario.
     */
    public List<SecurityEvent> executeScenario(SimulationScenario scenario) {
        List<SecurityEvent> scenarioEvents = new ArrayList<>();
        switch (scenario) {
            case RECON_AND_BRUTE_FORCE:
                scenarioEvents.addAll(launchPortScan("WS-001", "SRV-001", Arrays.asList(21, 22, 80, 443, 8080, 8443)));
                scenarioEvents.addAll(launchBruteForce("WS-001", "SRV-002", "root", 16));
                break;
            case DATA_EXFILTRATION_ANOMALY:
                scenarioEvents.addAll(launchSuspiciousConnection("WS-001", "SRV-002", 3306, 250, 0.05));
                break;
            case ADVANCED_PERSISTENT_THREAT:
                scenarioEvents.addAll(launchPortScan("WS-001", "RTR-001", Arrays.asList(22, 23, 53, 80, 161, 443, 8080, 8443)));
                scenarioEvents.addAll(launchBruteForce("WS-001", "SRV-001", "admin", 20));
                scenarioEvents.addAll(launchSuspiciousConnection("WS-001", "SRV-002", 3306, 400, 0.02));
                break;
            case BENIGN_TRAFFIC_BASELINE:
                scenarioEvents.addAll(launchPortScan("WS-002", "SRV-001", Arrays.asList(80, 443)));
                scenarioEvents.addAll(launchBruteForce("WS-002", "SRV-001", "admin", 2));
                break;
        }
        return scenarioEvents;
    }

    // ============================================================
    // PIPELINE & AUTOMATED DEFENSE EXECUTION
    // ============================================================

    /**
     * Runs the end-to-end detection, ML classification, and automated defense response cycle.
     */
    public List<DefenseResult> runEndToEndDefenseCycle() {
        long startTotal = System.nanoTime();

        // 1. Process pending queue in SecurityMonitor
        long startProc = System.nanoTime();
        monitor.processPendingEvents();
        evalCoordinator.getPerformanceEvaluator().recordEventProcessingTime(System.nanoTime() - startProc);

        List<SecurityAlert> activeAlerts = monitor.getAlertManager().getAllAlerts();

        // 2. Machine Learning inference
        latestPredictions.clear();
        if (mlEngine != null && !allSimulatedEvents.isEmpty()) {
            long startMl = System.nanoTime();
            latestPredictions.addAll(mlEngine.analyzeEvents(allSimulatedEvents));
            evalCoordinator.getPerformanceEvaluator().recordMlPredictionTime(System.nanoTime() - startMl);
        }

        // 3. Automated Defense response
        long startDef = System.nanoTime();
        List<DefenseResult> results = defenseCoordinator.coordinateResponses(activeAlerts, latestPredictions);
        evalCoordinator.getPerformanceEvaluator().recordDefenseActionTime(System.nanoTime() - startDef);

        evalCoordinator.getPerformanceEvaluator().setTotalEventsProcessed(allSimulatedEvents.size());
        return results;
    }

    /**
     * Generates formal evaluation report (Text & CSV metrics).
     */
    public String generateEvaluationReport(String title) {
        return evalCoordinator.runEvaluation(
                title,
                testInstances,
                mlEngine,
                monitor.getDetectionEngine(),
                allSimulatedEvents,
                monitor.getAlertManager().getAllAlerts(),
                latestPredictions,
                defenseCoordinator.getDefenseAgent().getResponseHistory(),
                defenseCoordinator.getIncidentManager().getAllIncidents(),
                vnet,
                topology
        );
    }

    /**
     * Resets the simulation to baseline state.
     */
    public void resetSimulation() {
        for (NetworkNode node : vnet.getAllDevices()) {
            node.setIsolated(false);
            node.activate();
        }
        allSimulatedEvents.clear();
        latestPredictions.clear();
        this.simEngine = new SimulationEngine(vnet, topology, "RedTeam-Adversary");
        initializeMonitoring();
        initializeDefense();
        initializeEvaluation();
    }

    // ============================================================
    // ACCESSORS
    // ============================================================

    public VirtualNetwork getVirtualNetwork() {
        return vnet;
    }

    public NetworkTopology getNetworkTopology() {
        return topology;
    }

    public SimulationEngine getSimulationEngine() {
        return simEngine;
    }

    public SecurityMonitor getSecurityMonitor() {
        return monitor;
    }

    public MLDetectionEngine getMLEngine() {
        return mlEngine;
    }

    public DefenseCoordinator getDefenseCoordinator() {
        return defenseCoordinator;
    }

    public EvaluationCoordinator getEvaluationCoordinator() {
        return evalCoordinator;
    }

    public List<SecurityEvent> getAllSimulatedEvents() {
        return Collections.unmodifiableList(allSimulatedEvents);
    }

    public List<ThreatPrediction> getLatestPredictions() {
        return Collections.unmodifiableList(latestPredictions);
    }

    public weka.core.Instances getTestInstances() {
        return testInstances;
    }
}
