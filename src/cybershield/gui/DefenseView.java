package cybershield.gui;

import cybershield.defense.DefenseResult;
import cybershield.defense.IncidentStatus;
import cybershield.defense.SecurityIncident;
import cybershield.service.DefenseService;
import cybershield.service.IncidentService;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;

import java.util.List;

/**
 * DefenseView — Incident Response and Automated Defense Containment screen.
 */
public class DefenseView extends VBox {

    private final DefenseService defenseService;
    private final IncidentService incidentService;
    private final Runnable onActionExecuted;

    private final TableView<SecurityIncident> incidentTable = new TableView<>();
    private final ObservableList<SecurityIncident> incidentList = FXCollections.observableArrayList();

    private final TableView<DefenseResult> auditTable = new TableView<>();
    private final ObservableList<DefenseResult> auditList = FXCollections.observableArrayList();

    public DefenseView(DefenseService defenseService,
                       IncidentService incidentService,
                       Runnable onActionExecuted) {
        this.defenseService = defenseService;
        this.incidentService = incidentService;
        this.onActionExecuted = onActionExecuted;

        setSpacing(16);
        setPadding(new Insets(20));
        buildUI();
        refresh();
    }

    private void buildUI() {
        // 1. Defense Action Bar
        HBox actionBar = new HBox(12);
        actionBar.setAlignment(Pos.CENTER_LEFT);

        Button btnAutoDefense = new Button("Run Automated Defense Cycle");
        btnAutoDefense.getStyleClass().add("button-primary");
        btnAutoDefense.setOnAction(e -> handleRunAutoDefense());

        Button btnBlock = new Button("Block Attacker Connection");
        btnBlock.getStyleClass().add("button-danger");
        btnBlock.setOnAction(e -> handleManualBlock());

        Button btnIsolate = new Button("Isolate Target Device");
        btnIsolate.getStyleClass().add("button-danger");
        btnIsolate.setOnAction(e -> handleManualIsolate());

        Button btnRestore = new Button("Restore Quarantined Device");
        btnRestore.getStyleClass().add("button-success");
        btnRestore.setOnAction(e -> handleManualRestore());

        Button btnRefresh = new Button("Refresh Incidents");
        btnRefresh.getStyleClass().add("button-secondary");
        btnRefresh.setOnAction(e -> refresh());

        actionBar.getChildren().addAll(btnAutoDefense, btnBlock, btnIsolate, btnRestore, btnRefresh);

        // 2. Incident Tracker Panel
        VBox incBox = new VBox(8);
        incBox.getStyleClass().add("cyber-panel");
        Label lblIncTitle = new Label("Active Incident Response Registry");
        lblIncTitle.getStyleClass().add("panel-heading");

        setupIncidentTable();
        incBox.getChildren().addAll(lblIncTitle, incidentTable);
        VBox.setVgrow(incidentTable, Priority.ALWAYS);

        // 3. Defense Audit Log Panel
        VBox auditBox = new VBox(8);
        auditBox.getStyleClass().add("cyber-panel");
        Label lblAuditTitle = new Label("Mitigation & Defense Audit History");
        lblAuditTitle.getStyleClass().add("panel-heading");

        setupAuditTable();
        auditBox.getChildren().addAll(lblAuditTitle, auditTable);
        auditBox.setPrefHeight(220);

        getChildren().addAll(actionBar, incBox, auditBox);
        VBox.setVgrow(incBox, Priority.ALWAYS);
    }

    private void setupIncidentTable() {
        TableColumn<SecurityIncident, String> colId = new TableColumn<>("Incident ID");
        colId.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getIncidentId()));
        colId.setPrefWidth(120);

        TableColumn<SecurityIncident, String> colStatus = new TableColumn<>("Current Status");
        colStatus.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getStatus().name()));
        colStatus.setPrefWidth(140);

        TableColumn<SecurityIncident, String> colAlert = new TableColumn<>("Trigger Alert");
        colAlert.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getPrimaryAlertId()));
        colAlert.setPrefWidth(130);

        TableColumn<SecurityIncident, String> colTarget = new TableColumn<>("Target Device");
        colTarget.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getTargetNodeId()));
        colTarget.setPrefWidth(130);

        TableColumn<SecurityIncident, String> colCreated = new TableColumn<>("Created At");
        colCreated.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getCreatedAt().toString()));
        colCreated.setPrefWidth(220);

        incidentTable.getColumns().addAll(colId, colStatus, colAlert, colTarget, colCreated);
        incidentTable.setItems(incidentList);
    }

    private void setupAuditTable() {
        TableColumn<DefenseResult, String> colId = new TableColumn<>("Action ID");
        colId.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getActionId()));
        colId.setPrefWidth(120);

        TableColumn<DefenseResult, String> colType = new TableColumn<>("Strategy Type");
        colType.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getActionType().name()));
        colType.setPrefWidth(160);

        TableColumn<DefenseResult, String> colTarget = new TableColumn<>("Target");
        colTarget.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getTargetId()));
        colTarget.setPrefWidth(120);

        TableColumn<DefenseResult, String> colResult = new TableColumn<>("Result");
        colResult.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().isSuccess() ? "SUCCESS" : "FAILED"));
        colResult.setPrefWidth(100);

        TableColumn<DefenseResult, String> colDesc = new TableColumn<>("Action Audit Summary");
        colDesc.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getResultDescription()));
        colDesc.setPrefWidth(420);

        auditTable.getColumns().addAll(colId, colType, colTarget, colResult, colDesc);
        auditTable.setItems(auditList);
    }

    private void handleRunAutoDefense() {
        List<DefenseResult> results = defenseService.executeAutomatedDefense();
        refresh();
        if (onActionExecuted != null) onActionExecuted.run();
        new Alert(Alert.AlertType.INFORMATION, "Automated Defense Cycle completed. " + results.size() + " containment actions executed.").showAndWait();
    }

    private void handleManualBlock() {
        SecurityIncident selected = incidentTable.getSelectionModel().getSelectedItem();
        String target = selected != null ? selected.getTargetNodeId() : "SRV-001";
        DefenseResult res = defenseService.manuallyBlockConnection("WS-001", target);
        refresh();
        if (onActionExecuted != null) onActionExecuted.run();
        new Alert(Alert.AlertType.INFORMATION, "Connection Blocked: " + res.getResultDescription()).showAndWait();
    }

    private void handleManualIsolate() {
        SecurityIncident selected = incidentTable.getSelectionModel().getSelectedItem();
        String target = selected != null ? selected.getTargetNodeId() : "WS-001";
        DefenseResult res = defenseService.manuallyIsolateDevice(target);
        if (selected != null) {
            incidentService.updateIncidentStatus(selected.getIncidentId(), IncidentStatus.CONTAINED, "Device quarantined manually.");
        }
        refresh();
        if (onActionExecuted != null) onActionExecuted.run();
        new Alert(Alert.AlertType.INFORMATION, "Device Quarantined: " + res.getResultDescription()).showAndWait();
    }

    private void handleManualRestore() {
        SecurityIncident selected = incidentTable.getSelectionModel().getSelectedItem();
        String target = selected != null ? selected.getTargetNodeId() : "WS-001";
        DefenseResult res = defenseService.manuallyRestoreDevice(target);
        if (selected != null) {
            incidentService.updateIncidentStatus(selected.getIncidentId(), IncidentStatus.RECOVERED, "Device restored manually.");
        }
        refresh();
        if (onActionExecuted != null) onActionExecuted.run();
        new Alert(Alert.AlertType.INFORMATION, "Device Restored: " + res.getResultDescription()).showAndWait();
    }

    public void refresh() {
        incidentList.setAll(incidentService.getAllIncidents());
        auditList.setAll(defenseService.getDefenseHistory());
    }
}
