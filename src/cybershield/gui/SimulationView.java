package cybershield.gui;

import cybershield.arena.SimulationScenario;
import cybershield.model.NetworkNode;
import cybershield.security.SecurityEvent;
import cybershield.service.NetworkDeviceService;
import cybershield.service.SimulationService;
import cybershield.service.ThreatDetectionService;
import javafx.application.Platform;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;

import java.util.Arrays;
import java.util.List;

/**
 * SimulationView — Attack Simulation Screen.
 * Demonstrates:
 *   - Asynchronous execution using javafx.concurrent.Task (UI thread never freezes).
 *   - Event handling for launching predefined scenarios and custom attack actions.
 *   - Real-time logging into TableView.
 */
public class SimulationView extends VBox {

    private final SimulationService simulationService;
    private final NetworkDeviceService deviceService;
    private final ThreatDetectionService detectionService;
    private final Runnable onSimulationCompleted;

    private final ComboBox<SimulationScenario> cmbScenario = new ComboBox<>();
    private final ComboBox<String> cmbSource = new ComboBox<>();
    private final ComboBox<String> cmbTarget = new ComboBox<>();
    private final ComboBox<String> cmbAttackType = new ComboBox<>();
    private final TextField txtParam = new TextField("15");

    private final Button btnRunScenario = new Button("Launch Scenario");
    private final Button btnRunCustom = new Button("Dispatch Attack Action");
    private final Button btnReset = new Button("Reset Sandbox");
    private final ProgressBar progressBar = new ProgressBar(0);
    private final Label lblStatus = new Label("Simulation Engine: IDLE (Safe Sandbox)");

    private final TableView<SecurityEvent> eventTable = new TableView<>();
    private final ObservableList<SecurityEvent> eventList = FXCollections.observableArrayList();

    public SimulationView(SimulationService simulationService,
                          NetworkDeviceService deviceService,
                          ThreatDetectionService detectionService,
                          Runnable onSimulationCompleted) {
        this.simulationService = simulationService;
        this.deviceService = deviceService;
        this.detectionService = detectionService;
        this.onSimulationCompleted = onSimulationCompleted;

        setSpacing(16);
        setPadding(new Insets(20));
        buildUI();
        refreshDevices();
    }

    private void buildUI() {
        // 1. Predefined Scenario Panel
        VBox scenarioPanel = new VBox(10);
        scenarioPanel.getStyleClass().add("cyber-panel");

        Label lblScenTitle = new Label("Pre-Configured Cyber Attack Scenarios");
        lblScenTitle.getStyleClass().add("panel-heading");

        HBox scenRow = new HBox(12);
        scenRow.setAlignment(Pos.CENTER_LEFT);

        cmbScenario.getItems().setAll(SimulationScenario.values());
        cmbScenario.setValue(SimulationScenario.RECON_AND_BRUTE_FORCE);
        cmbScenario.setPrefWidth(350);

        btnRunScenario.getStyleClass().add("button-primary");
        btnRunScenario.setOnAction(e -> handleRunScenario());

        btnReset.getStyleClass().add("button-danger");
        btnReset.setOnAction(e -> handleResetSimulation());

        progressBar.setPrefWidth(180);
        progressBar.setVisible(false);

        lblStatus.setStyle("-fx-text-fill: #8b949e; -fx-font-size: 12px;");

        scenRow.getChildren().addAll(cmbScenario, btnRunScenario, btnReset, progressBar, lblStatus);
        scenarioPanel.getChildren().addAll(lblScenTitle, scenRow);

        // 2. Custom Attack Injection Panel
        VBox customPanel = new VBox(10);
        customPanel.getStyleClass().add("cyber-panel");

        Label lblCustomTitle = new Label("Custom Synthetic Attack Injection");
        lblCustomTitle.getStyleClass().add("panel-heading");

        HBox customRow = new HBox(12);
        customRow.setAlignment(Pos.CENTER_LEFT);

        cmbAttackType.getItems().addAll("Port Scan", "Login Brute Force", "Suspicious Connection Burst");
        cmbAttackType.setValue("Port Scan");
        cmbAttackType.setPrefWidth(220);

        cmbSource.setPromptText("Source Node");
        cmbSource.setPrefWidth(160);

        cmbTarget.setPromptText("Target Node");
        cmbTarget.setPrefWidth(160);

        txtParam.setPromptText("Attempts / Ports");
        txtParam.setPrefWidth(120);

        btnRunCustom.getStyleClass().add("button-secondary");
        btnRunCustom.setOnAction(e -> handleRunCustomAttack());

        customRow.getChildren().addAll(cmbAttackType, cmbSource, cmbTarget, txtParam, btnRunCustom);
        customPanel.getChildren().addAll(lblCustomTitle, customRow);

        // 3. Live Simulation Event Log Table
        setupTable();

        getChildren().addAll(scenarioPanel, customPanel, eventTable);
        VBox.setVgrow(eventTable, Priority.ALWAYS);
    }

    private void setupTable() {
        TableColumn<SecurityEvent, String> colId = new TableColumn<>("Event ID");
        colId.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getEventId()));
        colId.setPrefWidth(100);

        TableColumn<SecurityEvent, String> colType = new TableColumn<>("Attack Vector");
        colType.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getAttackType().getDisplayLabel()));
        colType.setPrefWidth(170);

        TableColumn<SecurityEvent, String> colSrc = new TableColumn<>("Source Node");
        colSrc.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getSourceNodeId()));
        colSrc.setPrefWidth(110);

        TableColumn<SecurityEvent, String> colTgt = new TableColumn<>("Target Node");
        colTgt.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getTargetNodeId()));
        colTgt.setPrefWidth(110);

        TableColumn<SecurityEvent, String> colSev = new TableColumn<>("Severity");
        colSev.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getSeverity().name()));
        colSev.setPrefWidth(100);

        TableColumn<SecurityEvent, Number> colLogins = new TableColumn<>("Failed Logins");
        colLogins.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().getFailedLoginCount()));
        colLogins.setPrefWidth(110);

        TableColumn<SecurityEvent, Number> colConns = new TableColumn<>("Conn Attempts");
        colConns.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().getConnectionAttemptCount()));
        colConns.setPrefWidth(110);

        TableColumn<SecurityEvent, Number> colPorts = new TableColumn<>("Ports Probed");
        colPorts.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().getUniquePortCount()));
        colPorts.setPrefWidth(110);

        TableColumn<SecurityEvent, String> colDesc = new TableColumn<>("Description");
        colDesc.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getEventDescription()));
        colDesc.setPrefWidth(320);

        eventTable.getColumns().addAll(colId, colType, colSrc, colTgt, colSev, colLogins, colConns, colPorts, colDesc);
        eventTable.setItems(eventList);
    }

    private void handleRunScenario() {
        SimulationScenario selected = cmbScenario.getValue();
        if (selected == null) return;

        setControlsDisabled(true);
        progressBar.setVisible(true);
        lblStatus.setText("Executing scenario: " + selected.getTitle() + "...");

        Task<List<SecurityEvent>> task = new Task<>() {
            @Override
            protected List<SecurityEvent> call() throws Exception {
                // Background thread execution
                List<SecurityEvent> events = simulationService.runScenario(selected);
                // Trigger detection pipeline
                detectionService.processRuleBasedDetection();
                detectionService.runMachineLearningInference();
                return events;
            }
        };

        task.setOnSucceeded(e -> {
            List<SecurityEvent> events = task.getValue();
            eventList.addAll(events);
            setControlsDisabled(false);
            progressBar.setVisible(false);
            lblStatus.setText("Scenario complete. Generated " + events.size() + " events.");
            if (onSimulationCompleted != null) onSimulationCompleted.run();
        });

        task.setOnFailed(e -> {
            setControlsDisabled(false);
            progressBar.setVisible(false);
            lblStatus.setText("Scenario execution error.");
            new Alert(Alert.AlertType.ERROR, "Error: " + task.getException().getMessage()).showAndWait();
        });

        new Thread(task).start();
    }

    private void handleRunCustomAttack() {
        String type = cmbAttackType.getValue();
        String src = cmbSource.getValue();
        String tgt = cmbTarget.getValue();

        if (src == null || tgt == null) {
            new Alert(Alert.AlertType.WARNING, "Please select source and target nodes.").showAndWait();
            return;
        }

        int val = 15;
        try {
            val = Integer.parseInt(txtParam.getText().trim());
        } catch (NumberFormatException ignored) {}

        final int paramVal = val;
        setControlsDisabled(true);
        progressBar.setVisible(true);
        lblStatus.setText("Dispatching attack: " + type + "...");

        Task<List<SecurityEvent>> task = new Task<>() {
            @Override
            protected List<SecurityEvent> call() throws Exception {
                List<SecurityEvent> events;
                if ("Port Scan".equalsIgnoreCase(type)) {
                    events = simulationService.runPortScan(src, tgt, Arrays.asList(21, 22, 80, 443, 3306, 8080));
                } else if ("Login Brute Force".equalsIgnoreCase(type)) {
                    events = simulationService.runBruteForce(src, tgt, "root", paramVal);
                } else {
                    events = simulationService.runSuspiciousConnection(src, tgt, 8080, paramVal, 0.05);
                }
                detectionService.processRuleBasedDetection();
                detectionService.runMachineLearningInference();
                return events;
            }
        };

        task.setOnSucceeded(e -> {
            List<SecurityEvent> events = task.getValue();
            eventList.addAll(events);
            setControlsDisabled(false);
            progressBar.setVisible(false);
            lblStatus.setText("Attack action dispatched. " + events.size() + " events generated.");
            if (onSimulationCompleted != null) onSimulationCompleted.run();
        });

        task.setOnFailed(e -> {
            setControlsDisabled(false);
            progressBar.setVisible(false);
            lblStatus.setText("Attack execution failed.");
        });

        new Thread(task).start();
    }

    private void handleResetSimulation() {
        simulationService.resetSimulation();
        eventList.clear();
        lblStatus.setText("Sandbox reset to baseline state.");
        if (onSimulationCompleted != null) onSimulationCompleted.run();
    }

    public void refreshDevices() {
        List<NetworkNode> devices = deviceService.getAllDevices();
        ObservableList<String> ids = FXCollections.observableArrayList();
        for (NetworkNode d : devices) {
            ids.add(d.getNodeId());
        }
        cmbSource.setItems(ids);
        cmbTarget.setItems(ids);
        if (ids.size() >= 2) {
            cmbSource.setValue("WS-001");
            cmbTarget.setValue("SRV-001");
        }
    }

    private void setControlsDisabled(boolean disabled) {
        btnRunScenario.setDisable(disabled);
        btnRunCustom.setDisable(disabled);
        btnReset.setDisable(disabled);
        cmbScenario.setDisable(disabled);
    }
}
