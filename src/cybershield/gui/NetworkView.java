package cybershield.gui;

import cybershield.model.NetworkNode;
import cybershield.model.Router;
import cybershield.model.Server;
import cybershield.model.Workstation;
import cybershield.service.NetworkDeviceService;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;

import java.util.List;

/**
 * NetworkView — Device Management and Topology screen.
 * Allows adding, searching, isolating, restoring, and removing virtual network devices.
 */
public class NetworkView extends VBox {

    private final NetworkDeviceService deviceService;
    private final TableView<NetworkNode> deviceTable = new TableView<>();
    private final ObservableList<NetworkNode> tableData = FXCollections.observableArrayList();

    private final TextField txtSearch = new TextField();
    private final TextField txtId = new TextField();
    private final TextField txtName = new TextField();
    private final ComboBox<String> cmbType = new ComboBox<>();
    private final TextField txtIp = new TextField();

    public NetworkView(NetworkDeviceService deviceService) {
        this.deviceService = deviceService;
        setSpacing(16);
        setPadding(new Insets(20));
        buildUI();
        refresh();
    }

    private void buildUI() {
        // 1. Search and Action Header
        HBox header = new HBox(12);
        header.setAlignment(Pos.CENTER_LEFT);

        txtSearch.setPromptText("Search by Device ID, Name, or IP Address...");
        txtSearch.setPrefWidth(320);
        txtSearch.textProperty().addListener((obs, oldVal, newVal) -> filterDevices(newVal));

        Button btnRefresh = new Button("Refresh Devices");
        btnRefresh.getStyleClass().add("button-secondary");
        btnRefresh.setOnAction(e -> refresh());

        Button btnIsolate = new Button("Toggle Quarantine");
        btnIsolate.getStyleClass().add("button-danger");
        btnIsolate.setOnAction(e -> handleToggleIsolate());

        Button btnDelete = new Button("Remove Device");
        btnDelete.getStyleClass().add("button-secondary");
        btnDelete.setOnAction(e -> handleDeleteDevice());

        header.getChildren().addAll(txtSearch, btnRefresh, btnIsolate, btnDelete);

        // 2. Devices TableView
        setupTable();

        // 3. Add Device Panel
        VBox addPanel = new VBox(10);
        addPanel.getStyleClass().add("cyber-panel");
        Label lblPanelTitle = new Label("Register Virtual Network Device");
        lblPanelTitle.getStyleClass().add("panel-heading");

        HBox formRow = new HBox(12);
        formRow.setAlignment(Pos.CENTER_LEFT);

        txtId.setPromptText("Node ID (e.g. SRV-003)");
        txtId.setPrefWidth(160);

        txtName.setPromptText("Device Name (e.g. Mail Server)");
        txtName.setPrefWidth(220);

        cmbType.getItems().addAll("SERVER", "WORKSTATION", "ROUTER");
        cmbType.setValue("SERVER");
        cmbType.setPrefWidth(140);

        txtIp.setPromptText("IPv4 (e.g. 192.168.1.50)");
        txtIp.setPrefWidth(180);

        Button btnAdd = new Button("Add Device");
        btnAdd.getStyleClass().add("button-primary");
        btnAdd.setOnAction(e -> handleAddDevice());

        formRow.getChildren().addAll(txtId, txtName, cmbType, txtIp, btnAdd);
        addPanel.getChildren().addAll(lblPanelTitle, formRow);

        getChildren().addAll(header, deviceTable, addPanel);
        VBox.setVgrow(deviceTable, Priority.ALWAYS);
    }

    private void setupTable() {
        TableColumn<NetworkNode, String> colId = new TableColumn<>("Device ID");
        colId.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().getNodeId()));
        colId.setPrefWidth(120);

        TableColumn<NetworkNode, String> colName = new TableColumn<>("Device Name");
        colName.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().getNodeName()));
        colName.setPrefWidth(220);

        TableColumn<NetworkNode, String> colType = new TableColumn<>("Type");
        colType.setCellValueFactory(data -> new SimpleStringProperty(resolveType(data.getValue())));
        colType.setPrefWidth(140);

        TableColumn<NetworkNode, String> colIp = new TableColumn<>("IP Address");
        colIp.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().getIpAddress()));
        colIp.setPrefWidth(160);

        TableColumn<NetworkNode, String> colStatus = new TableColumn<>("Operational Status");
        colStatus.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().getStatus().name()));
        colStatus.setPrefWidth(150);

        TableColumn<NetworkNode, String> colIsolated = new TableColumn<>("Quarantine State");
        colIsolated.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().isIsolated() ? "ISOLATED" : "NORMAL"));
        colIsolated.setPrefWidth(140);

        deviceTable.getColumns().addAll(colId, colName, colType, colIp, colStatus, colIsolated);
        deviceTable.setItems(tableData);
    }

    private void handleAddDevice() {
        String id = txtId.getText().trim();
        String name = txtName.getText().trim();
        String type = cmbType.getValue();
        String ip = txtIp.getText().trim();

        if (id.isEmpty() || name.isEmpty() || ip.isEmpty()) {
            showAlert(Alert.AlertType.WARNING, "Validation Error", "All fields are required.");
            return;
        }

        try {
            NetworkNode node;
            switch (type) {
                case "SERVER":
                    node = new Server(id, name, ip, "SERVICE", 8080);
                    break;
                case "WORKSTATION":
                    node = new Workstation(id, name, ip, "Windows 11", "operator");
                    break;
                case "ROUTER":
                default:
                    node = new Router(id, name, ip, true);
                    break;
            }

            deviceService.registerDevice(node);
            txtId.clear();
            txtName.clear();
            txtIp.clear();
            refresh();
            showAlert(Alert.AlertType.INFORMATION, "Device Added", "Device " + id + " registered successfully.");

        } catch (Exception ex) {
            showAlert(Alert.AlertType.ERROR, "Registration Error", ex.getMessage());
        }
    }

    private void handleToggleIsolate() {
        NetworkNode selected = deviceTable.getSelectionModel().getSelectedItem();
        if (selected == null) {
            showAlert(Alert.AlertType.WARNING, "Selection Required", "Please select a device from the table.");
            return;
        }

        boolean targetIsolation = !selected.isIsolated();
        deviceService.updateDeviceIsolation(selected.getNodeId(), targetIsolation);
        refresh();

        String stateStr = targetIsolation ? "quarantined (ISOLATED)" : "restored to normal operation";
        showAlert(Alert.AlertType.INFORMATION, "Isolation Updated", "Device " + selected.getNodeId() + " is now " + stateStr + ".");
    }

    private void handleDeleteDevice() {
        NetworkNode selected = deviceTable.getSelectionModel().getSelectedItem();
        if (selected == null) {
            showAlert(Alert.AlertType.WARNING, "Selection Required", "Please select a device to remove.");
            return;
        }

        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION, "Are you sure you want to remove device " + selected.getNodeId() + "?", ButtonType.YES, ButtonType.NO);
        confirm.setHeaderText("Confirm Device Deletion");
        confirm.showAndWait().ifPresent(res -> {
            if (res == ButtonType.YES) {
                deviceService.removeDevice(selected.getNodeId());
                refresh();
            }
        });
    }

    private void filterDevices(String query) {
        List<NetworkNode> list = deviceService.searchDevices(query);
        tableData.setAll(list);
    }

    public void refresh() {
        tableData.setAll(deviceService.getAllDevices());
    }

    private String resolveType(NetworkNode node) {
        if (node instanceof Server) return "SERVER";
        if (node instanceof Workstation) return "WORKSTATION";
        if (node instanceof Router) return "ROUTER";
        return "GENERIC";
    }

    private void showAlert(Alert.AlertType type, String title, String content) {
        Alert alert = new Alert(type, content, ButtonType.OK);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.showAndWait();
    }
}
