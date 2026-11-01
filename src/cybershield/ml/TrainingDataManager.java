package cybershield.ml;

import weka.core.Instance;
import weka.core.Instances;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * TrainingDataManager — CyberShield Arena Phase 5
 *
 * OOP Concepts demonstrated:
 *   - Single Responsibility : Loads, validates, and splits the labelled CSV dataset.
 *   - Defensive Programming : Rejects malformed rows and invalid labels with clear messages.
 *   - Reproducibility       : Uses a fixed random seed so train/test splits are identical every run.
 *
 * ─── CSV Format ──────────────────────────────────────────────────────────────
 * The CSV must have exactly this header row (case-insensitive):
 *   failedLoginCount,connectionAttemptCount,uniquePortCount,severityLevel,attackTypeCode,label
 *
 * Columns:
 *   failedLoginCount      — integer >= 0
 *   connectionAttemptCount — integer >= 0
 *   uniquePortCount       — integer >= 0
 *   severityLevel         — integer 1–4 (1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL)
 *   attackTypeCode        — integer 0, 1, or 2  (0=PORT_SCAN, 1=LOGIN, 2=SUSPICIOUS_CONN)
 *   label                 — "NORMAL" or "SUSPICIOUS" (case-insensitive)
 *
 * ─── Train / Test Split ──────────────────────────────────────────────────────
 * The dataset is shuffled with a fixed seed before splitting so:
 *   - Results are reproducible across runs.
 *   - Training and test examples never overlap (no data leakage).
 *
 * IMPORTANT: This is a small synthetic dataset created for demonstration.
 * It does not represent real-world network traffic distributions.
 */
public class TrainingDataManager {

    private static final String EXPECTED_HEADER =
        "failedLoginCount,connectionAttemptCount,uniquePortCount,severityLevel,attackTypeCode,label";

    private Instances allInstances;
    private Instances trainingInstances;
    private Instances testInstances;

    private final MLFeatureExtractor featureExtractor = new MLFeatureExtractor();

    // ---------------------------------------------------------------
    // Loading
    // ---------------------------------------------------------------

    /**
     * Reads the CSV file, validates every row, and builds a Weka Instances dataset.
     * Malformed rows are skipped and a warning is printed — the rest are kept.
     *
     * @param csvPath path to the labelled CSV training file
     * @throws IOException if the file cannot be opened or has no valid rows
     */
    public void loadFromCsv(String csvPath) throws IOException {
        if (csvPath == null || csvPath.isBlank()) {
            throw new IllegalArgumentException("CSV file path must not be blank.");
        }
        if (!Files.exists(Paths.get(csvPath))) {
            throw new IOException("Training data file not found: " + csvPath);
        }

        Instances schema = featureExtractor.buildDatasetSchema("CyberShieldTrainingData");
        List<Instance> validRows = new ArrayList<>();
        int lineNumber = 0;
        int skippedRows = 0;

        try (BufferedReader reader = Files.newBufferedReader(Paths.get(csvPath))) {
            // ── Validate header ──────────────────────────────────────
            String headerLine = reader.readLine();
            lineNumber++;

            if (headerLine == null || headerLine.isBlank()) {
                throw new IOException("CSV file is empty: " + csvPath);
            }
            String normalizedHeader = headerLine.trim().replaceAll("\\s+", "").toLowerCase();
            String expectedNorm     = EXPECTED_HEADER.replaceAll("\\s+", "").toLowerCase();
            if (!normalizedHeader.equals(expectedNorm)) {
                throw new IOException(
                    "Invalid CSV header.\n  Expected : " + EXPECTED_HEADER +
                    "\n  Found    : " + headerLine.trim());
            }

            // ── Parse data rows ──────────────────────────────────────
            String line;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                line = line.trim();
                if (line.isEmpty()) continue; // skip blank lines silently

                try {
                    Instance instance = parseRow(line, schema, lineNumber);
                    validRows.add(instance);
                } catch (IllegalArgumentException e) {
                    System.err.printf("[TrainingDataManager] Skipping row %d — %s%n",
                            lineNumber, e.getMessage());
                    skippedRows++;
                }
            }
        }

        if (validRows.isEmpty()) {
            throw new IOException("No valid data rows found in: " + csvPath);
        }

        // Build the final Instances from all valid rows
        allInstances = new Instances(schema, validRows.size());
        for (Instance inst : validRows) {
            allInstances.add(inst);
        }
        allInstances.setClassIndex(allInstances.numAttributes() - 1);

        System.out.printf("[DATASET] Loaded %d valid examples from '%s'%s.%n",
                allInstances.size(), csvPath,
                skippedRows > 0 ? " (" + skippedRows + " rows skipped)" : "");
    }

    // ---------------------------------------------------------------
    // Train / Test split
    // ---------------------------------------------------------------

    /**
     * Shuffles and splits the loaded dataset into training and test sets.
     * A fixed seed of 42 is used to make the split reproducible.
     *
     * @param trainRatio fraction of examples to use for training, e.g. 0.80 = 80 %
     */
    public void splitTrainTest(double trainRatio) {
        splitTrainTest(trainRatio, 42L);
    }

    /**
     * Shuffles and splits the loaded dataset with a custom random seed.
     *
     * @param trainRatio fraction for training (must be in (0.0, 1.0))
     * @param seed       random seed — use the same value to reproduce the same split
     */
    public void splitTrainTest(double trainRatio, long seed) {
        if (allInstances == null) {
            throw new IllegalStateException("Dataset not loaded. Call loadFromCsv() first.");
        }
        if (trainRatio <= 0.0 || trainRatio >= 1.0) {
            throw new IllegalArgumentException(
                "Train ratio must be between 0.0 and 1.0 exclusive (got " + trainRatio + ").");
        }

        // Shuffle a copy — never modify the original order
        Instances shuffled = new Instances(allInstances);
        shuffled.randomize(new Random(seed));

        int trainSize = (int) Math.round(shuffled.size() * trainRatio);
        int testSize  = shuffled.size() - trainSize;

        trainingInstances = new Instances(shuffled, 0, trainSize);
        testInstances     = new Instances(shuffled, trainSize, testSize);

        System.out.printf("[DATASET] Training examples : %d%n", trainingInstances.size());
        System.out.printf("[DATASET] Test examples     : %d%n",  testInstances.size());
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    /**
     * Parses a single CSV data row into a labelled Weka Instance.
     * Throws IllegalArgumentException (with a clear message) on any problem.
     */
    private Instance parseRow(String line, Instances schema, int lineNumber) {
        String[] parts = line.split(",", -1);
        if (parts.length != 6) {
            throw new IllegalArgumentException(
                "Expected 6 comma-separated columns, found " + parts.length + ".");
        }

        try {
            double failedLogins  = parseNonNeg(parts[0].trim(), "failedLoginCount");
            double connAttempts  = parseNonNeg(parts[1].trim(), "connectionAttemptCount");
            double uniquePorts   = parseNonNeg(parts[2].trim(), "uniquePortCount");
            double severityLevel = parseSeverity(parts[3].trim());
            double attackCode    = parseAttackCode(parts[4].trim());
            PredictionClass label = parseLabel(parts[5].trim());

            double[] features = {failedLogins, connAttempts, uniquePorts, severityLevel, attackCode};
            return featureExtractor.createLabelledInstance(features, label, schema);

        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Non-numeric value — " + e.getMessage());
        }
    }

    private double parseNonNeg(String value, String field) {
        double d = Double.parseDouble(value);
        if (d < 0) throw new IllegalArgumentException(field + " cannot be negative (got " + d + ").");
        return d;
    }

    private double parseSeverity(String value) {
        double d = Double.parseDouble(value);
        if (d < 1 || d > 4) {
            throw new IllegalArgumentException("severityLevel must be 1–4 (got " + d + ").");
        }
        return d;
    }

    private double parseAttackCode(String value) {
        double d = Double.parseDouble(value);
        if (d < 0 || d > 2) {
            throw new IllegalArgumentException("attackTypeCode must be 0, 1, or 2 (got " + d + ").");
        }
        return d;
    }

    private PredictionClass parseLabel(String raw) {
        try {
            return PredictionClass.valueOf(raw.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "Unknown label '" + raw + "'. Valid values: NORMAL, SUSPICIOUS.");
        }
    }

    // ---------------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------------

    /** Returns all loaded examples (training + test combined, before splitting). */
    public Instances getAllInstances() {
        if (allInstances == null) throw new IllegalStateException("Dataset not loaded yet.");
        return allInstances;
    }

    /** Returns the training split. Requires splitTrainTest() to have been called. */
    public Instances getTrainingInstances() {
        if (trainingInstances == null)
            throw new IllegalStateException("Dataset not split yet. Call splitTrainTest() first.");
        return trainingInstances;
    }

    /** Returns the test split. Requires splitTrainTest() to have been called. */
    public Instances getTestInstances() {
        if (testInstances == null)
            throw new IllegalStateException("Dataset not split yet. Call splitTrainTest() first.");
        return testInstances;
    }
}
