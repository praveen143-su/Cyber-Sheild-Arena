package cybershield.arena;

import cybershield.defense.DefenseAuditLogger;
import cybershield.defense.IncidentResponseManager;
import cybershield.defense.SecurityIncident;
import cybershield.evaluation.EvaluationMetrics;
import cybershield.ml.PredictionClass;
import cybershield.ml.ThreatPrediction;
import cybershield.model.DeviceStatus;
import cybershield.model.NetworkNode;
import cybershield.model.Server;
import cybershield.model.Workstation;
import cybershield.monitoring.SecurityAlert;
import cybershield.monitoring.SecurityMonitor;
import cybershield.network.NetworkTopology;
import cybershield.network.VirtualNetwork;
import cybershield.security.FirewallRule;
import cybershield.security.SecurityEvent;

import java.util.Collection;
import java.util.List;

/**
 * ArenaDashboard — Visual terminal rendering and formatting utilities for CyberShield Arena.
 *
 * Provides structured ASCII tables, status indicators, progress meters,
 * and cybersecurity HUD (Heads-Up Display) panels.
 */
public final class ArenaDashboard {

    // ANSI Colors for enhanced terminal visualization
    public static final String ANSI_RESET  = "\u001B[0m";
    public static final String ANSI_BOLD   = "\u001B[1m";
    public static final String ANSI_RED    = "\u001B[31m";
    public static final String ANSI_GREEN  = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE   = "\u001B[34m";
    public static final String ANSI_CYAN   = "\u001B[36m";
    public static final String ANSI_WHITE  = "\u001B[37m";

    private ArenaDashboard() {
        // Static utility class
    }

    /**
     * Prints the master CyberShield Arena title banner.
     */
    public static void displayBanner() {
        System.out.println(ANSI_CYAN + ANSI_BOLD);
        System.out.println("  ==========================================================================================");
        System.out.println("   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ ");
        System.out.println("  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗");
        System.out.println("  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗███████║██║█████╗  ██║     ██║  ██║");
        System.out.println("  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║");
        System.out.println("  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║██║  ██║██║███████╗███████╗██████╔╝");
        System.out.println("   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ ");
        System.out.println("                         CYBER ATTACK VS DEFENSE ARENA (PHASE 8 FINAL)                      ");
        System.out.println("             Full Autonomous SOC, ML Detection, Automated Incident Response & HUD          ");
        System.out.println("  ==========================================================================================" + ANSI_RESET);
    }

    /**
     * Displays a clean section title header.
     */
    public static void displayHeader(String title) {
        System.out.println("\n" + ANSI_BLUE + ANSI_BOLD + ">>> " + title + ANSI_RESET);
        System.out.println(ANSI_BLUE + "-".repeat(88) + ANSI_RESET);
    }

    /**
     * Displays live virtual network devices and firewall policies in an ASCII grid.
     */
    public static void displayNetworkTopology(VirtualNetwork vnet, NetworkTopology topology) {
        displayHeader("VIRTUAL NETWORK TOPOLOGY & DEVICE HEALTH");
        Collection<NetworkNode> nodes = vnet.getAllDevices();

        System.out.printf(ANSI_BOLD + "%-10s | %-22s | %-15s | %-14s | %-10s | %-10s%n" + ANSI_RESET,
                "Node ID", "Device Name", "IP Address", "Device Role", "Status", "Isolation");
        System.out.println("-".repeat(92));

        for (NetworkNode node : nodes) {
            String role = "Router";
            if (node instanceof Server) {
                Server s = (Server) node;
                role = "Server (" + s.getServiceName() + ":" + s.getPortNumber() + ")";
            } else if (node instanceof Workstation) {
                Workstation w = (Workstation) node;
                role = "Workstation (" + w.getOperatingSystem() + ")";
            }

            boolean isOnline = node.getStatus() == DeviceStatus.ONLINE;
            String statusColor = isOnline ? ANSI_GREEN : ANSI_RED;
            String isoColor = node.isIsolated() ? ANSI_RED + ANSI_BOLD : ANSI_GREEN;

            System.out.printf("%-10s | %-22s | %-15s | %-14s | %s%-10s%s | %s%-10s%s%n",
                    node.getNodeId(),
                    node.getNodeName(),
                    node.getIpAddress(),
                    role,
                    statusColor, node.getStatus().name(), ANSI_RESET,
                    isoColor, (node.isIsolated() ? "ISOLATED" : "CONNECTED"), ANSI_RESET
            );
        }
        System.out.println("-".repeat(92));

        // Display Active Firewall Rules
        List<FirewallRule> rules = topology.getFirewallRules();
        System.out.println(ANSI_BOLD + "\n[ACTIVE PERIMETER FIREWALL RULES: " + rules.size() + " RULES ENFORCED]" + ANSI_RESET);
        System.out.printf("%-12s | %-12s | %-12s | %-10s%n", "Rule ID", "Source Node", "Target Node", "Action");
        System.out.println("-".repeat(54));
        for (FirewallRule rule : rules) {
            String actionColor = rule.getAction().name().equalsIgnoreCase("ALLOW") ? ANSI_GREEN : ANSI_RED;
            System.out.printf("%-12s | %-12s | %-12s | %s%-10s%s%n",
                    rule.getRuleId(),
                    rule.getSourceNodeId(),
                    rule.getTargetNodeId(),
                    actionColor, rule.getAction().name(), ANSI_RESET
            );
        }
    }

    /**
     * Renders the real-time SOC Alert and Threat Monitor.
     */
    public static void displaySOCStatus(SecurityMonitor monitor, IncidentResponseManager incidentManager) {
        displayHeader("SECURITY OPERATIONS CENTER (SOC) - LIVE THREAT FEED");

        int totalEvents = monitor.getEventProcessor().getTotalProcessedCount();
        int activeAlerts = monitor.getAlertManager().getTotalAlertCount();
        int totalIncidents = incidentManager.getTotalIncidentCount();
        int openIncidents = incidentManager.getOpenIncidents().size();
        int resolvedIncidents = incidentManager.getResolvedIncidents().size();

        System.out.printf("  [METRICS] Total Events Processed: %d | Total Alerts: %d | Incidents: %d (Active: %d, Resolved: %d)%n\n",
                totalEvents, activeAlerts, totalIncidents, openIncidents, resolvedIncidents);

        List<SecurityAlert> alerts = monitor.getAlertManager().getAllAlerts();
        if (alerts.isEmpty()) {
            System.out.println(ANSI_GREEN + "  [SECURE] No active security alerts. Network baseline normal." + ANSI_RESET);
            return;
        }

        System.out.printf(ANSI_BOLD + "%-14s | %-12s | %-12s | %-10s | %-10s | %s%n" + ANSI_RESET,
                "Alert ID", "Source", "Target", "Severity", "Risk Score", "Alert Title");
        System.out.println("-".repeat(92));

        for (SecurityAlert alert : alerts) {
            String sevColor;
            switch (alert.getSeverity()) {
                case CRITICAL: sevColor = ANSI_RED + ANSI_BOLD; break;
                case HIGH:     sevColor = ANSI_RED; break;
                case MEDIUM:   sevColor = ANSI_YELLOW; break;
                default:       sevColor = ANSI_WHITE; break;
            }

            System.out.printf("%-14s | %-12s | %-12s | %s%-10s%s | %-10d | %s%n",
                    alert.getAlertId(),
                    alert.getSourceNodeId(),
                    alert.getTargetNodeId(),
                    sevColor, alert.getSeverity().name(), ANSI_RESET,
                    alert.getRiskScore(),
                    alert.getAlertTitle()
            );
        }
    }

    /**
     * Renders Machine Learning predictions and decision confidence.
     */
    public static void displayMLPredictions(List<ThreatPrediction> predictions) {
        displayHeader("MACHINE LEARNING DECISION TREE INFERENCE ENGINE");

        if (predictions == null || predictions.isEmpty()) {
            System.out.println("  No ML predictions recorded in current buffer.");
            return;
        }

        System.out.printf(ANSI_BOLD + "%-12s | %-14s | %-18s | %s%n" + ANSI_RESET,
                "Event ID", "Classification", "Confidence Gauge", "Feature Summary");
        System.out.println("-".repeat(88));

        for (ThreatPrediction pred : predictions) {
            boolean suspicious = pred.getPredictedClass() == PredictionClass.SUSPICIOUS;
            String classColor = suspicious ? ANSI_RED + ANSI_BOLD : ANSI_GREEN;
            String gauge = renderProgressBar(pred.getConfidenceScore());

            System.out.printf("%-12s | %s%-14s%s | %s | %s%n",
                    pred.getEventId(),
                    classColor, pred.getPredictedClass().name(), ANSI_RESET,
                    gauge,
                    pred.getFeatureSummary()
            );
        }
    }

    /**
     * Renders incident management and automated response audit logs.
     */
    public static void displayIncidentRegistry(IncidentResponseManager incidentManager, DefenseAuditLogger logger) {
        displayHeader("AUTOMATED INCIDENT RESPONSE & DEFENSE AUDIT REGISTRY");

        List<SecurityIncident> incidents = incidentManager.getAllIncidents();
        if (incidents.isEmpty()) {
            System.out.println(ANSI_GREEN + "  [CLEAN] No incidents logged in the response manager." + ANSI_RESET);
            return;
        }

        System.out.printf(ANSI_BOLD + "%-12s | %-14s | %-12s | %-12s | %s%n" + ANSI_RESET,
                "Incident ID", "Status", "Attacker", "Victim", "Containment / Resolution Timeline");
        System.out.println("-".repeat(88));

        for (SecurityIncident inc : incidents) {
            String statusColor;
            switch (inc.getStatus()) {
                case CONTAINED: statusColor = ANSI_YELLOW + ANSI_BOLD; break;
                case RECOVERED:
                case CLOSED:    statusColor = ANSI_GREEN + ANSI_BOLD; break;
                default:        statusColor = ANSI_RED + ANSI_BOLD; break;
            }

            List<String> timeline = inc.getAuditTimeline();
            String summary = timeline.isEmpty() ? "Active investigation" : timeline.get(timeline.size() - 1);
            if (summary.length() > 50) {
                summary = summary.substring(0, 47) + "...";
            }

            System.out.printf("%-12s | %s%-14s%s | %-12s | %-12s | %s%n",
                    inc.getIncidentId(),
                    statusColor, inc.getStatus().name(), ANSI_RESET,
                    inc.getSourceNodeId(),
                    inc.getTargetNodeId(),
                    summary
            );
        }

        System.out.printf("\n  Audit Log CSV File: %s (RFC-4180 Format)%n", logger.getLogFilePath().toAbsolutePath());
    }

    /**
     * Displays a clean formatted table for evaluation metrics.
     */
    public static void displayEvaluationReport(EvaluationMetrics ruleMetrics, EvaluationMetrics mlMetrics) {
        displayHeader("EVALUATION & BENCHMARK PERFORMANCE METRICS");

        System.out.printf(ANSI_BOLD + "%-24s | %-25s | %-25s%n" + ANSI_RESET,
                "Metric Dimension", "Rule-Based Engine (P4)", "ML Decision Tree (P5)");
        System.out.println("-".repeat(80));

        System.out.printf("%-24s | %-25s | %-25s%n", "True Positives (TP)",
                ruleMetrics != null ? String.valueOf(ruleMetrics.getTruePositives()) : "N/A",
                mlMetrics != null ? String.valueOf(mlMetrics.getTruePositives()) : "N/A");
        System.out.printf("%-24s | %-25s | %-25s%n", "True Negatives (TN)",
                ruleMetrics != null ? String.valueOf(ruleMetrics.getTrueNegatives()) : "N/A",
                mlMetrics != null ? String.valueOf(mlMetrics.getTrueNegatives()) : "N/A");
        System.out.printf("%-24s | %-25s | %-25s%n", "False Positives (FP)",
                ruleMetrics != null ? String.valueOf(ruleMetrics.getFalsePositives()) : "N/A",
                mlMetrics != null ? String.valueOf(mlMetrics.getFalsePositives()) : "N/A");
        System.out.printf("%-24s | %-25s | %-25s%n", "False Negatives (FN)",
                ruleMetrics != null ? String.valueOf(ruleMetrics.getFalseNegatives()) : "N/A",
                mlMetrics != null ? String.valueOf(mlMetrics.getFalseNegatives()) : "N/A");
        System.out.println("-".repeat(80));

        System.out.printf("%-24s | %-25s | %-25s%n", "Accuracy",
                ruleMetrics != null ? String.format("%.2f%%", ruleMetrics.getAccuracy() * 100) : "N/A",
                mlMetrics != null ? String.format("%.2f%%", mlMetrics.getAccuracy() * 100) : "N/A");
        System.out.printf("%-24s | %-25s | %-25s%n", "Precision",
                ruleMetrics != null ? String.format("%.2f%%", ruleMetrics.getPrecision() * 100) : "N/A",
                mlMetrics != null ? String.format("%.2f%%", mlMetrics.getPrecision() * 100) : "N/A");
        System.out.printf("%-24s | %-25s | %-25s%n", "Recall (Sensitivity)",
                ruleMetrics != null ? String.format("%.2f%%", ruleMetrics.getRecall() * 100) : "N/A",
                mlMetrics != null ? String.format("%.2f%%", mlMetrics.getRecall() * 100) : "N/A");
        System.out.printf("%-24s | %-25s | %-25s%n", "F1 Score",
                ruleMetrics != null ? String.format("%.4f", ruleMetrics.getF1Score()) : "N/A",
                mlMetrics != null ? String.format("%.4f", mlMetrics.getF1Score()) : "N/A");
        System.out.printf("%-24s | %-25s | %-25s%n", "False Positive Rate (FPR)",
                ruleMetrics != null ? String.format("%.2f%%", ruleMetrics.getFalsePositiveRate() * 100) : "N/A",
                mlMetrics != null ? String.format("%.2f%%", mlMetrics.getFalsePositiveRate() * 100) : "N/A");
        System.out.println("-".repeat(80));
    }

    /**
     * Renders a 10-block visual progress meter. E.g.: [████████░░] 80.0%
     */
    public static String renderProgressBar(double score) {
        double bounded = Math.max(0.0, Math.min(1.0, score));
        int totalBlocks = 10;
        int filled = (int) Math.round(bounded * totalBlocks);
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < filled; i++) {
            sb.append("█");
        }
        for (int i = filled; i < totalBlocks; i++) {
            sb.append("░");
        }
        sb.append(String.format("] %5.1f%%", bounded * 100));
        return sb.toString();
    }
}
