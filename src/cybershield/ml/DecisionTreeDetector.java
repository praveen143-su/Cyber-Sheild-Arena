package cybershield.ml;

import weka.classifiers.trees.J48;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.SerializationHelper;

import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * DecisionTreeDetector — CyberShield Arena Phase 5
 *
 * OOP Concepts demonstrated:
 *   - Implements ThreatDetectionModel (Interface Polymorphism)
 *   - Encapsulation : The J48 classifier object is private. Callers never touch it directly.
 *   - State machine : the object has two states — untrained and trained.
 *                     predict() is only valid in the trained state.
 *
 * ─── What is J48 / C4.5? ─────────────────────────────────────────────────────
 * J48 is Weka's implementation of the C4.5 decision-tree algorithm (Ross Quinlan, 1993).
 * A decision tree learns by repeatedly asking "which feature best splits the data here?"
 * and building a tree of if-then-else rules.
 *
 * Example of a learned rule:
 *   IF uniquePortCount >= 10  → SUSPICIOUS
 *   ELSE IF failedLoginCount >= 10 → SUSPICIOUS
 *   ELSE → NORMAL
 *
 * ─── Key Hyperparameters ─────────────────────────────────────────────────────
 *   Confidence Factor (0.25) — controls how aggressively the tree is pruned.
 *     A smaller value → smaller tree → less overfitting.
 *     0.25 is the C4.5 default and works well on small datasets.
 *
 *   Minimum instances per leaf (2) — a leaf must cover at least 2 training examples.
 *     Prevents the tree from memorising single rare examples.
 *
 * ─── Model Persistence ───────────────────────────────────────────────────────
 * The trained J48 classifier is saved using Java serialisation.
 * On the next run, loadModel() can restore it so retraining is skipped.
 * The saved file also stores the attribute schema so schema compatibility can be verified.
 */
public class DecisionTreeDetector implements ThreatDetectionModel {

    /** Identifier for this model implementation. */
    public static final String MODEL_ID = "J48-DecisionTree-v1";

    private J48 classifier;
    private Instances trainingDataHeader; // schema (attribute definitions), no data rows
    private boolean trained = false;

    private final MLFeatureExtractor featureExtractor = new MLFeatureExtractor();

    // ---------------------------------------------------------------
    // Training
    // ---------------------------------------------------------------

    /**
     * Trains the J48 Decision Tree on labelled Instances.
     *
     * This is the step where the algorithm analyses the training rows, finds the
     * best feature splits, and builds the if-then-else tree structure.
     *
     * @param trainingData Weka Instances with class attribute set — must not be empty
     * @throws Exception if Weka's training routine encounters an error
     */
    @Override
    public void train(Instances trainingData) throws Exception {
        if (trainingData == null || trainingData.isEmpty()) {
            throw new IllegalArgumentException("Training data must not be null or empty.");
        }
        if (trainingData.classIndex() < 0) {
            throw new IllegalArgumentException(
                "Training data must have a class attribute set (classIndex < 0).");
        }

        System.out.println("[MODEL] Initialising J48 Decision Tree...");

        classifier = new J48();
        classifier.setConfidenceFactor(0.25f); // C4.5 standard pruning confidence
        classifier.setMinNumObj(2);             // minimum training instances per leaf
        classifier.setUnpruned(false);          // apply reduced-error pruning

        // Save the schema (column names + class def) — needed for live prediction
        trainingDataHeader = new Instances(trainingData, 0); // 0 rows = header only

        classifier.buildClassifier(trainingData);
        trained = true;

        System.out.println("[MODEL] J48 training completed successfully.");
        System.out.println("[MODEL] Learned decision tree structure:");
        System.out.println(classifier.toString());
    }

    // ---------------------------------------------------------------
    // Prediction
    // ---------------------------------------------------------------

    /**
     * Classifies a single unseen event and returns a ThreatPrediction.
     *
     * Steps:
     *   1. Wrap the feature array in a Weka Instance (using the saved schema).
     *   2. Ask the classifier for the predicted class index.
     *   3. Ask for the probability distribution over both classes.
     *   4. Package everything in a ThreatPrediction.
     *
     * @param eventId  ID from the original SecurityEvent (for tracking only — NOT a feature)
     * @param features double[5] matching the training column order
     * @return ThreatPrediction with class label and confidence score
     * @throws Exception if classification fails
     */
    @Override
    public ThreatPrediction predict(String eventId, double[] features) throws Exception {
        if (!trained) {
            throw new IllegalStateException("Model has not been trained. Call train() first.");
        }
        if (features == null || features.length != MLFeatureExtractor.FEATURE_COUNT) {
            throw new IllegalArgumentException(
                "Feature array must have exactly " + MLFeatureExtractor.FEATURE_COUNT +
                " values (got " + (features == null ? "null" : features.length) + ").");
        }

        // Build a Weka Instance from the feature values
        Instance instance = featureExtractor.createUnlabelledInstance(features, trainingDataHeader);

        // classifyInstance() returns the numeric class index (0 = NORMAL, 1 = SUSPICIOUS)
        double classIndex = classifier.classifyInstance(instance);

        // distributionForInstance() returns [P(NORMAL), P(SUSPICIOUS)]
        double[] distribution = classifier.distributionForInstance(instance);

        // Map the class index back to our enum
        PredictionClass predictedClass;
        int normalIdx = trainingDataHeader.classAttribute().indexOfValue(PredictionClass.NORMAL.name());
        predictedClass = ((int) classIndex == normalIdx)
                ? PredictionClass.NORMAL
                : PredictionClass.SUSPICIOUS;

        // confidence = the model's probability for the chosen class
        double confidence = distribution[(int) classIndex];

        String featureSummary = featureExtractor.buildFeatureSummary(features);

        return new ThreatPrediction(eventId, predictedClass, confidence, MODEL_ID, featureSummary);
    }

    // ---------------------------------------------------------------
    // Model persistence
    // ---------------------------------------------------------------

    /**
     * Serialises the trained classifier AND the attribute schema to a single file.
     * Both are needed on reload: the schema verifies compatibility.
     *
     * @param filePath destination path, e.g. "models/cybershield_dt.model"
     */
    @Override
    public void saveModel(String filePath) throws Exception {
        if (!trained) {
            throw new IllegalStateException("Cannot save: model has not been trained yet.");
        }
        // Create parent directory if it does not exist
        if (Paths.get(filePath).getParent() != null) {
            Files.createDirectories(Paths.get(filePath).getParent());
        }
        // Save classifier and header together as an Object array
        SerializationHelper.write(filePath, new Object[]{classifier, trainingDataHeader});
        System.out.println("[MODEL] Model saved to: " + filePath);
    }

    /**
     * Loads a previously serialised model and verifies that its attribute schema
     * is compatible with the current MLFeatureExtractor (same number of features).
     *
     * @param filePath path to the saved model file
     * @throws Exception if the file is missing, corrupt, or has an incompatible schema
     */
    @Override
    public void loadModel(String filePath) throws Exception {
        Object[] loaded = (Object[]) SerializationHelper.read(filePath);
        if (loaded == null || loaded.length < 2) {
            throw new IllegalArgumentException(
                "Invalid model file (expected classifier + header): " + filePath);
        }

        J48 loadedClassifier     = (J48) loaded[0];
        Instances loadedHeader   = (Instances) loaded[1];

        // Schema compatibility check — class attribute counts as 1 extra column
        int storedFeatureCount = loadedHeader.numAttributes() - 1;
        if (storedFeatureCount != MLFeatureExtractor.FEATURE_COUNT) {
            throw new IllegalArgumentException(
                "Loaded model has " + storedFeatureCount + " features but extractor expects " +
                MLFeatureExtractor.FEATURE_COUNT + ". Retrain the model.");
        }

        this.classifier        = loadedClassifier;
        this.trainingDataHeader = loadedHeader;
        this.trained            = true;
        System.out.println("[MODEL] Model loaded from: " + filePath);
    }

    // ---------------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------------

    @Override public String getModelId()             { return MODEL_ID; }
    @Override public boolean isTrained()             { return trained; }
    @Override public Instances getTrainingDataHeader() { return trainingDataHeader; }

    /**
     * Exposes the underlying Weka J48 classifier.
     * This is needed by ModelEvaluator, which calls Weka's Evaluation.evaluateModel().
     */
    public J48 getClassifier() {
        if (!trained) throw new IllegalStateException("Classifier not trained yet.");
        return classifier;
    }
}
