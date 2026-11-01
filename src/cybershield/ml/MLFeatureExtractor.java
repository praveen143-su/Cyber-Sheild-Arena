package cybershield.ml;

import cybershield.security.AttackType;
import cybershield.security.SecurityEvent;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;

import java.util.ArrayList;

/**
 * MLFeatureExtractor — CyberShield Arena Phase 5
 *
 * OOP Concepts demonstrated:
 *   - Single Responsibility : This class has exactly one job — convert SecurityEvent objects
 *                             into numeric feature vectors that a Weka model can understand.
 *   - Consistency guarantee : The SAME transformation is applied during training and prediction.
 *                             If training used severityLevel=3 for HIGH, prediction must too.
 *
 * ─── What is a Feature Vector? ───────────────────────────────────────────────
 * Machine learning models cannot read Java objects.  They work with numbers.
 * A feature vector is just a row of numbers, one per "column" (feature).
 * For example:
 *
 *   [ failedLogins=15, connAttempts=15, uniquePorts=1, severityLevel=3, attackTypeCode=1 ]
 *
 * The model learns which combinations of numbers tend to be SUSPICIOUS vs NORMAL.
 *
 * ─── Feature Choices ─────────────────────────────────────────────────────────
 *   1. failedLoginCount      — how many login attempts failed (high = brute-force indicator)
 *   2. connectionAttemptCount — how many connection attempts were made (high = persistent probe)
 *   3. uniquePortCount       — how many distinct ports were scanned (high = port-scan indicator)
 *   4. severityLevel         — 1 (LOW) → 4 (CRITICAL), numeric encoding of Severity enum
 *   5. attackTypeCode        — 0 (PORT_SCAN), 1 (LOGIN_ATTACK), 2 (SUSPICIOUS_CONNECTION)
 *
 * ─── Deliberately EXCLUDED features ─────────────────────────────────────────
 *   Event ID  — unique identifier, would cause data leakage (model memorises IDs not patterns)
 *   Timestamp — time of day is not a reliable indicator in this simulation
 *   Node IDs  — source/target labels are not generalisable attack indicators
 */
public class MLFeatureExtractor {

    /** Human-readable names for each feature, in column order. */
    public static final String[] FEATURE_NAMES = {
        "failedLoginCount",
        "connectionAttemptCount",
        "uniquePortCount",
        "severityLevel",
        "attackTypeCode"
    };

    /** Total number of numeric feature columns (excluding the class label). */
    public static final int FEATURE_COUNT = FEATURE_NAMES.length;

    // Class label values — order determines Weka's internal class indices.
    // NORMAL = index 0, SUSPICIOUS = index 1.
    private static final ArrayList<String> CLASS_VALUES;
    static {
        CLASS_VALUES = new ArrayList<>();
        CLASS_VALUES.add(PredictionClass.NORMAL.name());      // index 0
        CLASS_VALUES.add(PredictionClass.SUSPICIOUS.name());  // index 1
    }

    // ---------------------------------------------------------------
    // Feature extraction
    // ---------------------------------------------------------------

    /**
     * Converts a SecurityEvent into a fixed-length double array.
     * The same method must be called for both training examples and live events.
     *
     * @param event the event to convert
     * @return double[5] — [failedLogins, connAttempts, uniquePorts, severityLevel, attackTypeCode]
     */
    public double[] extractFeatures(SecurityEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("Cannot extract features from a null SecurityEvent.");
        }
        double[] features = new double[FEATURE_COUNT];
        features[0] = Math.max(0, event.getFailedLoginCount());
        features[1] = Math.max(0, event.getConnectionAttemptCount());
        features[2] = Math.max(0, event.getUniquePortCount());
        features[3] = event.getSeverity().getLevel();    // 1 = LOW, 2 = MEDIUM, 3 = HIGH, 4 = CRITICAL
        features[4] = encodeAttackType(event.getAttackType());
        return features;
    }

    /**
     * Encodes an AttackType enum value as a numeric code.
     * PORT_SCAN = 0, LOGIN_ATTACK = 1, SUSPICIOUS_CONNECTION = 2.
     */
    public static double encodeAttackType(AttackType type) {
        return switch (type) {
            case PORT_SCAN             -> 0.0;
            case LOGIN_ATTACK          -> 1.0;
            case SUSPICIOUS_CONNECTION -> 2.0;
        };
    }

    /**
     * Decodes a numeric attack-type code back to an AttackType enum.
     * Used when reconstructing pseudo-SecurityEvents from CSV rows for comparison.
     */
    public static AttackType decodeAttackType(int code) {
        return switch (code) {
            case 0  -> AttackType.PORT_SCAN;
            case 1  -> AttackType.LOGIN_ATTACK;
            case 2  -> AttackType.SUSPICIOUS_CONNECTION;
            default -> AttackType.SUSPICIOUS_CONNECTION;
        };
    }

    // ---------------------------------------------------------------
    // Weka dataset construction
    // ---------------------------------------------------------------

    /**
     * Builds an EMPTY Weka Instances object with the correct attribute schema.
     * Think of this as creating a spreadsheet with the right column headings but no rows.
     *
     * The schema contains:
     *   5 numeric feature columns + 1 nominal class column (NORMAL / SUSPICIOUS)
     *
     * @param relationName a label for the dataset (stored inside the Instances object)
     * @return empty Instances with class index set to the last column
     */
    public Instances buildDatasetSchema(String relationName) {
        ArrayList<Attribute> attributes = new ArrayList<>();

        // Five numeric feature attributes
        for (String name : FEATURE_NAMES) {
            attributes.add(new Attribute(name));
        }

        // Nominal class attribute — the column the model tries to predict
        attributes.add(new Attribute("label", new ArrayList<>(CLASS_VALUES)));

        Instances schema = new Instances(relationName, attributes, 0);
        schema.setClassIndex(schema.numAttributes() - 1); // last column = class
        return schema;
    }

    /**
     * Creates a Weka Instance that has NO class label set.
     * Used during live prediction when we don't know the answer yet.
     *
     * @param features numeric feature array (length must equal FEATURE_COUNT)
     * @param schema   the Instances schema the instance must belong to
     * @return an Instance ready for classification
     */
    public Instance createUnlabelledInstance(double[] features, Instances schema) {
        if (features == null || features.length != FEATURE_COUNT) {
            throw new IllegalArgumentException(
                "Expected " + FEATURE_COUNT + " features but got " +
                (features == null ? "null" : features.length) + ".");
        }
        // Allocate one slot per attribute (features + class column)
        double[] values = new double[schema.numAttributes()];
        System.arraycopy(features, 0, values, 0, FEATURE_COUNT);
        values[FEATURE_COUNT] = Double.NaN; // NaN = "missing value" in Weka — class is unknown

        DenseInstance instance = new DenseInstance(1.0, values);
        instance.setDataset(schema); // links the instance to the schema for attribute lookup
        return instance;
    }

    /**
     * Creates a Weka Instance WITH a known class label.
     * Used when building training and test datasets where the ground truth is known.
     *
     * @param features numeric feature array
     * @param label    the correct class label (NORMAL or SUSPICIOUS)
     * @param schema   the Instances schema
     * @return a labelled Instance ready to be added to a training/test set
     */
    public Instance createLabelledInstance(double[] features, PredictionClass label, Instances schema) {
        double[] values = new double[schema.numAttributes()];
        System.arraycopy(features, 0, values, 0, FEATURE_COUNT);
        // classAttribute().indexOfValue("NORMAL") returns 0; "SUSPICIOUS" returns 1
        values[FEATURE_COUNT] = schema.classAttribute().indexOfValue(label.name());

        DenseInstance instance = new DenseInstance(1.0, values);
        instance.setDataset(schema);
        return instance;
    }

    // ---------------------------------------------------------------
    // Utility
    // ---------------------------------------------------------------

    /**
     * Produces a short human-readable summary of a feature vector for logging.
     * Example: "failedLogins=15 connAttempts=15 uniquePorts=1 severity=3 attackType=Login Attack"
     */
    public String buildFeatureSummary(double[] features) {
        return String.format(
            "failedLogins=%d connAttempts=%d uniquePorts=%d severity=%d attackType=%s",
            (int) features[0], (int) features[1], (int) features[2],
            (int) features[3],
            decodeAttackType((int) features[4]).getDisplayLabel()
        );
    }
}
