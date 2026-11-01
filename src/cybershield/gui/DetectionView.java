package cybershield.gui;

import cybershield.ml.ThreatPrediction;
import cybershield.monitoring.SecurityAlert;
import cybershield.security.SecurityEvent;
import cybershield.service.SimulationService;
import cybershield.service.ThreatDetectionService;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;

import java.util.List;
import java.util.Optional;

/**
 * DetectionView — Threat Detection & Machine Learning Comparison Screen.
 * Demonstrates:
 *   - Rich filtering (Attack vector, Severity, Keyword search).
 *   - Dual Detection Inspection: Rule-Based Logic vs Decision Tree ML Inference.
 */
public class DetectionView extends VBox {

    private final ThreatDetectionService detectionService;
    private final SimulationService simulationService;

    private final TableView<SecurityEvent> eventTable = new TableView<>();
    private final ObservableList<SecurityEvent> filteredEvents = FXCollections.observableArrayList();

    private final ComboBox<String> cmbFilterType = new ComboBox<>();
    private final ComboBox<String> cmbFilterSeverity = new ComboBox<>();
    private final TextField txtSearch = new TextField();

    // Inspection Labels (Rule-Based)
    private final Label lblAlertTitle = new Label("Select an event above to inspect");
    private final Label lblRuleId = new Label("-");
    private final Label lblRiskScore = new Label("0 / 100");
    private final ProgressBar barRiskScore = new ProgressBar(0);
    private final TextArea txtRuleExplanation = new TextArea();

    // Inspection Labels (Machine Learning)
    private final Label lblMlClass = new Label("-");
    private final Label lblMlConfidence = new Label("0.0%");
    private final ProgressBar barMlConfidence = new ProgressBar(0);
    private final Label lblMlModel = new Label("-");
    private final TextArea txtMlFeatures = new TextArea();

    public DetectionView(ThreatDetectionService detectionService, SimulationService simulationService) {
        this.detectionService = detectionService;
        this.simulationService = simulationService;

        setSpacing(16);
        setPadding(new Insets(20));
        buildUI();
        refresh();
    }

    private void buildUI() {
        // 1. Filter Toolbar
        HBox filterBar = new HBox(12);
        filterBar.setAlignment(Pos.CENTER_LEFT);

        txtSearch.setPromptText("Filter by Device ID or keyword...");
        txtSearch.setPrefWidth(260);
        txtSearch.textProperty().addListener((obs, old, val) -> applyFilter());

        cmbFilterType.getItems().addAll("ALL", "Port Scan", "Login Attack", "Suspicious Connection");
        cmbFilterType.setValue("ALL");
        cmbFilterType.setPrefWidth(180);
        cmbFilterType.valueProperty().addListener((obs, old, val) -> applyFilter());

        cmbFilterSeverity.getItems().addAll("ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL");
        cmbFilterSeverity.setValue("ALL");
        cmbFilterSeverity.setPrefWidth(140);
        cmbFilterSeverity.valueProperty().addListener((obs, old, val) -> applyFilter());

        Button btnRefresh = new Button("Apply Filter");
        btnRefresh.getStyleClass().add("button-secondary");
        btnRefresh.setOnAction(e -> applyFilter());

        filterBar.getChildren().addAll(txtSearch, cmbFilterType, cmbFilterSeverity, btnRefresh);

        // 2. Events TableView
        setupTable();

        // 3. Dual Detection Comparison Split
        HBox comparisonRow = new HBox(16);
        comparisonRow.setPrefHeight(260);

        // Rule-Based Box
        VBox ruleBox = new VBox(8);
        ruleBox.getStyleClass().add("cyber-panel");
        HBox.setHgrow(ruleBox, Priority.ALWAYS);

        Label lblRuleHeader = new Label("RULE-BASED DETECTION RESULT");
        lblRuleHeader.getStyleClass().add("panel-heading");

        GridPane ruleGrid = new GridPane();
        ruleGrid.setHgap(10);
        ruleGrid.setVgap(6);
        ruleGrid.add(new Label("Alert:"), 0, 0);
        ruleGrid.add(lblAlertTitle, 1, 0);
        ruleGrid.add(new Label("Rule ID:"), 0, 1);
        ruleGrid.add(lblRuleId, 1, 1);
        ruleGrid.add(new Label("Risk Score:"), 0, 2);

        HBox riskBox = new HBox(8, lblRiskScore, barRiskScore);
        riskBox.setAlignment(Pos.CENTER_LEFT);
        barRiskScore.setPrefWidth(120);
        ruleGrid.add(riskBox, 1, 2);

        txtRuleExplanation.setEditable(false);
        txtRuleExplanation.setWrapText(true);
        txtRuleExplanation.setPrefRowCount(3);

        ruleBox.getChildren().addAll(lblRuleHeader, ruleGrid, new Label("Rule Reasoning:"), txtRuleExplanation);

        // ML Box
        VBox mlBox = new VBox(8);
        mlBox.getStyleClass().add("cyber-panel");
        HBox.setHgrow(mlBox, Priority.ALWAYS);

        Label lblMlHeader = new Label("MACHINE LEARNING PREDICTION (WEKA J48)");
        lblMlHeader.getStyleClass().add("panel-heading");

        GridPane mlGrid = new GridPane();
        mlGrid.setHgap(10);
        mlGrid.setVgap(6);
        mlGrid.add(new Label("Predicted Class:"), 0, 0);
        lblMlClass.setStyle("-fx-font-weight: bold;");
        mlGrid.add(lblMlClass, 1, 0);

        mlGrid.add(new Label("Confidence:"), 0, 1);
        HBox confBox = new HBox(8, lblMlConfidence, barMlConfidence);
        confBox.setAlignment(Pos.CENTER_LEFT);
        barMlConfidence.setPrefWidth(120);
        mlGrid.add(confBox, 1, 1);

        mlGrid.add(new Label("Model ID:"), 0, 2);
        mlGrid.add(lblMlModel, 1, 2);

        txtMlFeatures.setEditable(false);
        txtMlFeatures.setWrapText(true);
        txtMlFeatures.setPrefRowCount(3);

        mlBox.getChildren().addAll(lblMlHeader, mlGrid, new Label("Model Feature Vector:"), txtMlFeatures);

        comparisonRow.getChildren().addAll(ruleBox, mlBox);

        getChildren().addAll(filterBar, eventTable, comparisonRow);
        VBox.setVgrow(eventTable, Priority.ALWAYS);
    }

    private void setupTable() {
        TableColumn<SecurityEvent, String> colId = new TableColumn<>("Event ID");
        colId.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getEventId()));
        colId.setPrefWidth(100);

        TableColumn<SecurityEvent, String> colType = new TableColumn<>("Attack Vector");
        colType.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getAttackType().getDisplayLabel()));
        colType.setPrefWidth(180);

        TableColumn<SecurityEvent, String> colSrc = new TableColumn<>("Source");
        colSrc.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getSourceNodeId()));
        colSrc.setPrefWidth(110);

        TableColumn<SecurityEvent, String> colTgt = new TableColumn<>("Target");
        colTgt.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getTargetNodeId()));
        colTgt.setPrefWidth(110);

        TableColumn<SecurityEvent, String> colSev = new TableColumn<>("Severity");
        colSev.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getSeverity().name()));
        colSev.setPrefWidth(100);

        TableColumn<SecurityEvent, String> colDesc = new TableColumn<>("Description");
        colDesc.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getEventDescription()));
        colDesc.setPrefWidth(420);

        eventTable.getColumns().addAll(colId, colType, colSrc, colTgt, colSev, colDesc);
        eventTable.setItems(filteredEvents);

        eventTable.getSelectionModel().selectedItemProperty().addListener((obs, old, selected) -> {
            if (selected != null) {
                inspectEvent(selected);
            }
        });
    }

    private void inspectEvent(SecurityEvent ev) {
        // 1. Inspect Rule-Based alert
        Optional<SecurityAlert> alertOpt = detectionService.getAllAlerts().stream()
                .filter(a -> a.getEventId().equalsIgnoreCase(ev.getEventId()))
                .findFirst();

        if (alertOpt.isPresent()) {
            SecurityAlert alert = alertOpt.get();
            lblAlertTitle.setText(alert.getAlertTitle());
            lblAlertTitle.setStyle("-fx-text-fill: #ef4444; -fx-font-weight: bold;");
            lblRuleId.setText(String.join(", ", alert.getAssociatedRuleIds()));
            lblRiskScore.setText(alert.getRiskScore() + " / 100");
            barRiskScore.setProgress(alert.getRiskScore() / 100.0);
            txtRuleExplanation.setText(alert.getExplanation());
        } else {
            lblAlertTitle.setText("No Rule Match (Benign or below threshold)");
            lblAlertTitle.setStyle("-fx-text-fill: #10b981; -fx-font-weight: bold;");
            lblRuleId.setText("None");
            lblRiskScore.setText("0 / 100");
            barRiskScore.setProgress(0);
            txtRuleExplanation.setText("Telemetry features did not violate any configured threat rules.");
        }

        // 2. Inspect Machine Learning prediction
        Optional<ThreatPrediction> predOpt = detectionService.getLatestPredictions().stream()
                .filter(p -> p.getEventId().equalsIgnoreCase(ev.getEventId()))
                .findFirst();

        if (predOpt.isPresent()) {
            ThreatPrediction pred = predOpt.get();
            lblMlClass.setText(pred.getPredictedClass().name());
            if (pred.getPredictedClass().name().equals("SUSPICIOUS")) {
                lblMlClass.setStyle("-fx-text-fill: #ef4444; -fx-font-weight: bold;");
            } else {
                lblMlClass.setStyle("-fx-text-fill: #10b981; -fx-font-weight: bold;");
            }
            lblMlConfidence.setText(String.format("%.1f%%", pred.getConfidenceScore() * 100));
            barMlConfidence.setProgress(pred.getConfidenceScore());
            lblMlModel.setText(pred.getModelId());
            txtMlFeatures.setText(pred.getFeatureSummary());
        } else {
            lblMlClass.setText("PENDING / NORMAL");
            lblMlClass.setStyle("-fx-text-fill: #8b949e;");
            lblMlConfidence.setText("N/A");
            barMlConfidence.setProgress(0);
            lblMlModel.setText("Weka-J48");
            txtMlFeatures.setText("Logins=" + ev.getFailedLoginCount() + ", Conns=" + ev.getConnectionAttemptCount() + ", Ports=" + ev.getUniquePortCount());
        }
    }

    public void applyFilter() {
        String query = txtSearch.getText().trim().toLowerCase();
        String typeFilter = cmbFilterType.getValue();
        String sevFilter = cmbFilterSeverity.getValue();

        List<SecurityEvent> all = simulationService.getAllSimulatedEvents();
        filteredEvents.clear();

        for (SecurityEvent ev : all) {
            boolean matchesQuery = query.isEmpty() ||
                    ev.getEventId().toLowerCase().contains(query) ||
                    ev.getSourceNodeId().toLowerCase().contains(query) ||
                    ev.getTargetNodeId().toLowerCase().contains(query) ||
                    ev.getEventDescription().toLowerCase().contains(query);

            boolean matchesType = typeFilter == null || typeFilter.equals("ALL") ||
                    ev.getAttackType().getDisplayLabel().equalsIgnoreCase(typeFilter);

            boolean matchesSev = sevFilter == null || sevFilter.equals("ALL") ||
                    ev.getSeverity().name().equalsIgnoreCase(sevFilter);

            if (matchesQuery && matchesType && matchesSev) {
                filteredEvents.add(ev);
            }
        }
    }

    public void refresh() {
        applyFilter();
    }
}
