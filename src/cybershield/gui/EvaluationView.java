package cybershield.gui;

import cybershield.evaluation.EvaluationMetrics;
import cybershield.service.EvaluationService;
import cybershield.service.ReportService;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;

import java.io.File;

/**
 * EvaluationView — Performance Benchmarking, Confusion Matrix & Reporting screen.
 */
public class EvaluationView extends VBox {

    private final EvaluationService evaluationService;
    private final ReportService reportService;

    // Confusion Matrix Labels
    private final Label lblTP = new Label("0");
    private final Label lblFP = new Label("0");
    private final Label lblFN = new Label("0");
    private final Label lblTN = new Label("0");

    // Metric Labels
    private final Label lblAccuracy = new Label("0.0%");
    private final Label lblPrecision = new Label("0.0%");
    private final Label lblRecall = new Label("0.0%");
    private final Label lblF1 = new Label("0.0%");
    private final Label lblFpr = new Label("0.0%");

    private final TableView<EvaluationMetrics> comparisonTable = new TableView<>();
    private final ObservableList<EvaluationMetrics> comparisonList = FXCollections.observableArrayList();
    private final Label lblReportPath = new Label("No report generated yet.");

    public EvaluationView(EvaluationService evaluationService, ReportService reportService) {
        this.evaluationService = evaluationService;
        this.reportService = reportService;

        setSpacing(16);
        setPadding(new Insets(20));
        buildUI();
        refresh();
    }

    private void buildUI() {
        // 1. Export Action Bar
        HBox exportBar = new HBox(12);
        exportBar.setAlignment(Pos.CENTER_LEFT);

        Button btnGenReport = new Button("Generate Session Audit Report");
        btnGenReport.getStyleClass().add("button-primary");
        btnGenReport.setOnAction(e -> handleGenerateReport());

        Button btnRefresh = new Button("Refresh Metrics");
        btnRefresh.getStyleClass().add("button-secondary");
        btnRefresh.setOnAction(e -> refresh());

        lblReportPath.setStyle("-fx-text-fill: #10b981; -fx-font-size: 12px;");

        exportBar.getChildren().addAll(btnGenReport, btnRefresh, lblReportPath);

        // 2. Metrics & Confusion Matrix Row
        HBox topRow = new HBox(20);

        // Confusion Matrix Panel
        VBox matrixPanel = new VBox(10);
        matrixPanel.getStyleClass().add("cyber-panel");
        matrixPanel.setPrefWidth(360);

        Label lblMatrixTitle = new Label("CONFUSION MATRIX (GROUND TRUTH VS ML)");
        lblMatrixTitle.getStyleClass().add("panel-heading");

        GridPane matrixGrid = new GridPane();
        matrixGrid.setHgap(8);
        matrixGrid.setVgap(8);
        matrixGrid.setAlignment(Pos.CENTER);

        matrixGrid.add(createMatrixCell("True Positive (TP)\n[Attack -> Detected]", lblTP, "kpi-accent-green"), 0, 0);
        matrixGrid.add(createMatrixCell("False Positive (FP)\n[Normal -> False Alarm]", lblFP, "kpi-accent-amber"), 1, 0);
        matrixGrid.add(createMatrixCell("False Negative (FN)\n[Attack -> Missed]", lblFN, "kpi-accent-red"), 0, 1);
        matrixGrid.add(createMatrixCell("True Negative (TN)\n[Normal -> Benign]", lblTN, "kpi-accent-cyan"), 1, 1);

        matrixPanel.getChildren().addAll(lblMatrixTitle, matrixGrid);

        // Performance Metrics Cards Grid
        GridPane metricsGrid = new GridPane();
        metricsGrid.setHgap(12);
        metricsGrid.setVgap(12);
        HBox.setHgrow(metricsGrid, Priority.ALWAYS);

        metricsGrid.add(createMetricCard("Accuracy", lblAccuracy, "kpi-accent-cyan"), 0, 0);
        metricsGrid.add(createMetricCard("Precision", lblPrecision, "kpi-accent-green"), 1, 0);
        metricsGrid.add(createMetricCard("Recall (Sensitivity)", lblRecall, "kpi-accent-green"), 2, 0);
        metricsGrid.add(createMetricCard("F1-Score", lblF1, "kpi-accent-cyan"), 0, 1);
        metricsGrid.add(createMetricCard("False Positive Rate", lblFpr, "kpi-accent-amber"), 1, 1);
        metricsGrid.add(createMetricCard("Evaluation Status", new Label("VALIDATED"), "kpi-accent-green"), 2, 1);

        for (int i = 0; i < 3; i++) {
            ColumnConstraints col = new ColumnConstraints();
            col.setPercentWidth(33.33);
            metricsGrid.getColumnConstraints().add(col);
        }

        topRow.getChildren().addAll(matrixPanel, metricsGrid);

        // 3. Comparison Table Panel
        VBox tableBox = new VBox(8);
        tableBox.getStyleClass().add("cyber-panel");
        Label lblCompTitle = new Label("Comparative Detector Performance Benchmark");
        lblCompTitle.getStyleClass().add("panel-heading");

        setupComparisonTable();
        tableBox.getChildren().addAll(lblCompTitle, comparisonTable);
        VBox.setVgrow(comparisonTable, Priority.ALWAYS);

        getChildren().addAll(exportBar, topRow, tableBox);
        VBox.setVgrow(tableBox, Priority.ALWAYS);
    }

    private VBox createMatrixCell(String title, Label valueLabel, String accentClass) {
        VBox box = new VBox(4);
        box.setAlignment(Pos.CENTER);
        box.setStyle("-fx-background-color: #0d111a; -fx-padding: 10; -fx-background-radius: 6; -fx-border-color: #232d3f; -fx-border-radius: 6;");
        box.setPrefWidth(160);
        box.setPrefHeight(75);

        Label lbl = new Label(title);
        lbl.setStyle("-fx-font-size: 10px; -fx-text-fill: #8b949e; -fx-text-alignment: center;");
        lbl.setWrapText(true);

        valueLabel.setStyle("-fx-font-size: 18px; -fx-font-weight: bold;");
        if (accentClass != null && !accentClass.isBlank()) {
            valueLabel.getStyleClass().add(accentClass);
        }

        box.getChildren().addAll(lbl, valueLabel);
        return box;
    }

    private VBox createMetricCard(String title, Label valueLabel, String accentClass) {
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

    private void setupComparisonTable() {
        TableColumn<EvaluationMetrics, String> colModel = new TableColumn<>("Detector Architecture");
        colModel.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getModelName()));
        colModel.setPrefWidth(220);

        TableColumn<EvaluationMetrics, String> colAcc = new TableColumn<>("Accuracy");
        colAcc.setCellValueFactory(d -> new SimpleStringProperty(String.format("%.2f%%", d.getValue().getAccuracy() * 100)));
        colAcc.setPrefWidth(120);

        TableColumn<EvaluationMetrics, String> colPrec = new TableColumn<>("Precision");
        colPrec.setCellValueFactory(d -> new SimpleStringProperty(String.format("%.2f%%", d.getValue().getPrecision() * 100)));
        colPrec.setPrefWidth(120);

        TableColumn<EvaluationMetrics, String> colRec = new TableColumn<>("Recall");
        colRec.setCellValueFactory(d -> new SimpleStringProperty(String.format("%.2f%%", d.getValue().getRecall() * 100)));
        colRec.setPrefWidth(120);

        TableColumn<EvaluationMetrics, String> colF1 = new TableColumn<>("F1-Score");
        colF1.setCellValueFactory(d -> new SimpleStringProperty(String.format("%.2f%%", d.getValue().getF1Score() * 100)));
        colF1.setPrefWidth(120);

        TableColumn<EvaluationMetrics, String> colFpr = new TableColumn<>("False Positive Rate");
        colFpr.setCellValueFactory(d -> new SimpleStringProperty(String.format("%.2f%%", d.getValue().getFalsePositiveRate() * 100)));
        colFpr.setPrefWidth(140);

        comparisonTable.getColumns().addAll(colModel, colAcc, colPrec, colRec, colF1, colFpr);
        comparisonTable.setItems(comparisonList);
    }

    private void handleGenerateReport() {
        try {
            String reportId = reportService.generateReport("Master Session Evaluation");
            String path = reportService.getReportFilePath(reportId);
            lblReportPath.setText("Report Generated: " + path);
            refresh();
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Report Generated");
            alert.setHeaderText("Session Audit Report Successfully Exported");
            alert.setContentText("Report ID: " + reportId + "\nLocation: " + new File(path).getAbsolutePath());
            alert.showAndWait();
        } catch (Exception ex) {
            new Alert(Alert.AlertType.ERROR, "Report Generation Error: " + ex.getMessage()).showAndWait();
        }
    }

    public void refresh() {
        EvaluationMetrics mlMetrics = evaluationService.getMlMetrics();
        EvaluationMetrics ruleMetrics = evaluationService.getRuleBasedMetrics();

        comparisonList.clear();
        if (ruleMetrics != null) comparisonList.add(ruleMetrics);
        if (mlMetrics != null) comparisonList.add(mlMetrics);

        if (mlMetrics != null) {
            lblTP.setText(String.valueOf(mlMetrics.getTruePositives()));
            lblFP.setText(String.valueOf(mlMetrics.getFalsePositives()));
            lblFN.setText(String.valueOf(mlMetrics.getFalseNegatives()));
            lblTN.setText(String.valueOf(mlMetrics.getTrueNegatives()));

            lblAccuracy.setText(String.format("%.1f%%", mlMetrics.getAccuracy() * 100));
            lblPrecision.setText(String.format("%.1f%%", mlMetrics.getPrecision() * 100));
            lblRecall.setText(String.format("%.1f%%", mlMetrics.getRecall() * 100));
            lblF1.setText(String.format("%.1f%%", mlMetrics.getF1Score() * 100));
            lblFpr.setText(String.format("%.1f%%", mlMetrics.getFalsePositiveRate() * 100));
        } else if (ruleMetrics != null) {
            lblTP.setText(String.valueOf(ruleMetrics.getTruePositives()));
            lblFP.setText(String.valueOf(ruleMetrics.getFalsePositives()));
            lblFN.setText(String.valueOf(ruleMetrics.getFalseNegatives()));
            lblTN.setText(String.valueOf(ruleMetrics.getTrueNegatives()));

            lblAccuracy.setText(String.format("%.1f%%", ruleMetrics.getAccuracy() * 100));
            lblPrecision.setText(String.format("%.1f%%", ruleMetrics.getPrecision() * 100));
            lblRecall.setText(String.format("%.1f%%", ruleMetrics.getRecall() * 100));
            lblF1.setText(String.format("%.1f%%", ruleMetrics.getF1Score() * 100));
            lblFpr.setText(String.format("%.1f%%", ruleMetrics.getFalsePositiveRate() * 100));
        }
    }
}
