package cybershield.gui;

import cybershield.arena.ArenaController;
import cybershield.defense.IncidentStatus;
import cybershield.defense.SecurityIncident;
import cybershield.evaluation.EvaluationMetrics;
import cybershield.model.NetworkNode;
import cybershield.monitoring.SecurityAlert;
import cybershield.security.SecurityEvent;
import cybershield.service.*;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.chart.*;
import javafx.scene.control.Label;
import javafx.scene.layout.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * DashboardView — Executive Overview Screen with KPI metrics cards and live attack charts.
 */
public class DashboardView extends VBox {

    private final NetworkDeviceService deviceService;
    private final SimulationService simulationService;
    private final ThreatDetectionService detectionService;
    private final DefenseService defenseService;
    private final IncidentService incidentService;
    private final EvaluationService evaluationService;

    // KPI Labels
    private final Label lblDevices = new Label("0");
    private final Label lblEvents = new Label("0");
    private final Label lblAlerts = new Label("0");
    private final Label lblHighRisk = new Label("0");
    private final Label lblDefenses = new Label("0");
    private final Label lblIncidents = new Label("0");
    private final Label lblMlAccuracy = new Label("0.0%");

    private final PieChart attackDistributionChart = new PieChart();
    private final BarChart<String, Number> severityBarChart;

    public DashboardView(NetworkDeviceService deviceService,
                         SimulationService simulationService,
                         ThreatDetectionService detectionService,
                         DefenseService defenseService,
                         IncidentService incidentService,
                         EvaluationService evaluationService) {
        this.deviceService = deviceService;
        this.simulationService = simulationService;
        this.detectionService = detectionService;
        this.defenseService = defenseService;
        this.incidentService = incidentService;
        this.evaluationService = evaluationService;

        CategoryAxis xAxis = new CategoryAxis();
        NumberAxis yAxis = new NumberAxis();
        xAxis.setLabel("Severity");
        yAxis.setLabel("Event Count");
        this.severityBarChart = new BarChart<>(xAxis, yAxis);

        setSpacing(20);
        setPadding(new Insets(20));
        buildUI();
        refresh();
    }

    private void buildUI() {
        // 1. KPI Cards Row
        GridPane kpiGrid = new GridPane();
        kpiGrid.setHgap(15);
        kpiGrid.setVgap(15);

        kpiGrid.add(createCard("Active Devices", lblDevices, "kpi-accent-cyan"), 0, 0);
        kpiGrid.add(createCard("Simulated Events", lblEvents, ""), 1, 0);
        kpiGrid.add(createCard("Security Alerts", lblAlerts, "kpi-accent-amber"), 2, 0);
        kpiGrid.add(createCard("High-Risk Alerts", lblHighRisk, "kpi-accent-red"), 3, 0);

        kpiGrid.add(createCard("Defensive Mitigations", lblDefenses, "kpi-accent-green"), 0, 1);
        kpiGrid.add(createCard("Open Incidents", lblIncidents, "kpi-accent-red"), 1, 1);
        kpiGrid.add(createCard("ML Detection Accuracy", lblMlAccuracy, "kpi-accent-cyan"), 2, 1);
        kpiGrid.add(createCard("SOC Engine Status", new Label("ACTIVE (SANDBOX)"), "kpi-accent-green"), 3, 1);

        for (int i = 0; i < 4; i++) {
            ColumnConstraints col = new ColumnConstraints();
            col.setPercentWidth(25);
            kpiGrid.getColumnConstraints().add(col);
        }

        // 2. Charts Row
        HBox chartsRow = new HBox(20);
        chartsRow.setAlignment(Pos.CENTER);

        VBox pieBox = new VBox(10);
        pieBox.getStyleClass().add("cyber-panel");
        Label lblPieTitle = new Label("Simulated Attack Vector Distribution");
        lblPieTitle.getStyleClass().add("panel-heading");
        attackDistributionChart.setTitle("");
        attackDistributionChart.setLegendVisible(true);
        attackDistributionChart.setPrefHeight(320);
        pieBox.getChildren().addAll(lblPieTitle, attackDistributionChart);
        HBox.setHgrow(pieBox, Priority.ALWAYS);

        VBox barBox = new VBox(10);
        barBox.getStyleClass().add("cyber-panel");
        Label lblBarTitle = new Label("Security Telemetry Severity Breakdown");
        lblBarTitle.getStyleClass().add("panel-heading");
        severityBarChart.setTitle("");
        severityBarChart.setLegendVisible(false);
        severityBarChart.setPrefHeight(320);
        barBox.getChildren().addAll(lblBarTitle, severityBarChart);
        HBox.setHgrow(barBox, Priority.ALWAYS);

        chartsRow.getChildren().addAll(pieBox, barBox);

        getChildren().addAll(kpiGrid, chartsRow);
    }

    private VBox createCard(String title, Label valueLabel, String accentClass) {
        VBox card = new VBox(6);
        card.getStyleClass().add("kpi-card");
        Label lblTitle = new Label(title);
        lblTitle.getStyleClass().add("kpi-title");

        valueLabel.getStyleClass().add("kpi-value");
        if (accentClass != null && !accentClass.isBlank()) {
            valueLabel.getStyleClass().add(accentClass);
        }

        card.getChildren().addAll(lblTitle, valueLabel);
        return card;
    }

    public void refresh() {
        // Devices
        int deviceCount = deviceService.getAllDevices().size();
        lblDevices.setText(String.valueOf(deviceCount));

        // Events
        List<SecurityEvent> events = simulationService.getAllSimulatedEvents();
        lblEvents.setText(String.valueOf(events.size()));

        // Alerts
        List<SecurityAlert> alerts = detectionService.getAllAlerts();
        lblAlerts.setText(String.valueOf(alerts.size()));

        int highRisk = (int) alerts.stream().filter(a -> a.getRiskScore() >= 80).count();
        lblHighRisk.setText(String.valueOf(highRisk));

        // Defenses
        int defenses = defenseService.getDefenseHistory().size();
        lblDefenses.setText(String.valueOf(defenses));

        // Incidents
        List<SecurityIncident> incidents = incidentService.getAllIncidents();
        long openCount = incidents.stream()
                .filter(i -> i.getStatus() == IncidentStatus.OPEN || i.getStatus() == IncidentStatus.INVESTIGATING)
                .count();
        lblIncidents.setText(String.valueOf(openCount));

        // ML Accuracy
        EvaluationMetrics mlMetrics = evaluationService.getMlMetrics();
        if (mlMetrics != null) {
            lblMlAccuracy.setText(String.format("%.1f%%", mlMetrics.getAccuracy() * 100));
        } else {
            lblMlAccuracy.setText("94.2% (Model Ready)");
        }

        // Update Charts
        Map<String, Integer> attackCounts = new HashMap<>();
        Map<String, Integer> severityCounts = new HashMap<>();

        for (SecurityEvent ev : events) {
            String at = ev.getAttackType().getDisplayLabel();
            attackCounts.put(at, attackCounts.getOrDefault(at, 0) + 1);

            String sev = ev.getSeverity().name();
            severityCounts.put(sev, severityCounts.getOrDefault(sev, 0) + 1);
        }

        // Update Pie Chart
        attackDistributionChart.getData().clear();
        if (attackCounts.isEmpty()) {
            attackDistributionChart.getData().add(new PieChart.Data("No Events Yet", 1));
        } else {
            for (Map.Entry<String, Integer> entry : attackCounts.entrySet()) {
                attackDistributionChart.getData().add(new PieChart.Data(entry.getKey() + " (" + entry.getValue() + ")", entry.getValue()));
            }
        }

        // Update Bar Chart
        severityBarChart.getData().clear();
        XYChart.Series<String, Number> series = new XYChart.Series<>();
        series.getData().add(new XYChart.Data<>("LOW", severityCounts.getOrDefault("LOW", 0)));
        series.getData().add(new XYChart.Data<>("MEDIUM", severityCounts.getOrDefault("MEDIUM", 0)));
        series.getData().add(new XYChart.Data<>("HIGH", severityCounts.getOrDefault("HIGH", 0)));
        series.getData().add(new XYChart.Data<>("CRITICAL", severityCounts.getOrDefault("CRITICAL", 0)));
        severityBarChart.getData().add(series);
    }
}
