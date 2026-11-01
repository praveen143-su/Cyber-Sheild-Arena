package cybershield.ml;

import weka.core.Instances;

import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * ModelManager — CyberShield Arena Phase 5
 *
 * OOP Concepts demonstrated:
 *   - Manager / Controller Pattern : Single point of control for model lifecycle.
 *   - Lazy Initialisation          : The model is trained on demand, not at construction time.
 *   - Defensive State Management   : Throws clear exceptions when callers try to use an
 *                                    un-trained model or a missing file.
 *
 * ─── Responsibilities ────────────────────────────────────────────────────────
 *   1. Create the DecisionTreeDetector.
 *   2. Train it when explicitly requested.
 *   3. Save the trained model to disk.
 *   4. Load a previously saved model (avoids unnecessary retraining on repeat runs).
 *   5. Expose the trained model to the rest of the application.
 *
 * ─── Typical usage ───────────────────────────────────────────────────────────
 *   ModelManager mgr = new ModelManager();
 *   if (!mgr.tryLoadModel("models/cybershield_dt.model")) {
 *       mgr.initializeAndTrain(trainingInstances);
 *       mgr.saveModel("models/cybershield_dt.model");
 *   }
 *   ThreatDetectionModel model = mgr.getModel();
 */
public class ModelManager {

    private static final String DEFAULT_MODEL_PATH = "models/cybershield_dt.model";

    private DecisionTreeDetector detector;
    private boolean modelReady = false;

    public ModelManager() {
        detector = new DecisionTreeDetector();
    }

    // ---------------------------------------------------------------
    // Training
    // ---------------------------------------------------------------

    /**
     * Trains a fresh Decision Tree on the provided training data.
     * Any previously loaded or trained model is discarded.
     *
     * @param trainingData labelled Weka Instances from TrainingDataManager
     * @throws Exception if training fails
     */
    public void initializeAndTrain(Instances trainingData) throws Exception {
        if (trainingData == null || trainingData.isEmpty()) {
            throw new IllegalArgumentException("Training data must not be null or empty.");
        }
        System.out.println("[ModelManager] Beginning model training...");
        detector = new DecisionTreeDetector(); // fresh instance
        detector.train(trainingData);
        modelReady = true;
        System.out.println("[ModelManager] Model is ready for predictions.");
    }

    // ---------------------------------------------------------------
    // Persistence
    // ---------------------------------------------------------------

    /**
     * Saves the trained model to the default path ("models/cybershield_dt.model").
     *
     * @throws Exception if saving fails or the model is not yet trained
     */
    public void saveModel() throws Exception {
        saveModel(DEFAULT_MODEL_PATH);
    }

    /**
     * Saves the trained model to the specified file path.
     * The parent directory is created automatically.
     *
     * @param filePath destination path for the serialised model
     * @throws Exception if saving fails or the model is not yet trained
     */
    public void saveModel(String filePath) throws Exception {
        if (!modelReady) {
            throw new IllegalStateException("Cannot save: model has not been trained yet.");
        }
        detector.saveModel(filePath);
    }

    /**
     * Attempts to load a previously trained model from the default path.
     *
     * @return true if the model was loaded successfully; false if the file is missing or incompatible
     */
    public boolean tryLoadModel() {
        return tryLoadModel(DEFAULT_MODEL_PATH);
    }

    /**
     * Attempts to load a previously trained model from the given file.
     * If loading fails, the failure is reported and the manager remains untrained
     * so the caller knows to retrain.
     *
     * @param filePath path to the saved model file
     * @return true if loaded successfully, false otherwise
     */
    public boolean tryLoadModel(String filePath) {
        if (filePath == null || filePath.isBlank()) {
            System.err.println("[ModelManager] Model file path is blank — cannot load.");
            return false;
        }
        if (!Files.exists(Paths.get(filePath))) {
            System.out.println("[ModelManager] No saved model found at: " + filePath + " — will train.");
            return false;
        }
        try {
            detector = new DecisionTreeDetector();
            detector.loadModel(filePath);
            modelReady = true;
            return true;
        } catch (Exception e) {
            System.err.println("[ModelManager] Failed to load model: " + e.getMessage());
            System.err.println("[ModelManager] The model will be retrained.");
            modelReady = false;
            return false;
        }
    }

    // ---------------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------------

    /**
     * Returns the trained model as a ThreatDetectionModel interface.
     * Use this when only predict() calls are needed.
     *
     * @throws IllegalStateException if the model has not been trained or loaded
     */
    public ThreatDetectionModel getModel() {
        requireReady();
        return detector;
    }

    /**
     * Returns the underlying DecisionTreeDetector directly.
     * Needed by ModelEvaluator, which requires access to the J48 classifier.
     *
     * @throws IllegalStateException if the model has not been trained or loaded
     */
    public DecisionTreeDetector getDetector() {
        requireReady();
        return detector;
    }

    /** Returns true if the model is trained and ready to accept predictions. */
    public boolean isModelReady() { return modelReady; }

    private void requireReady() {
        if (!modelReady) {
            throw new IllegalStateException(
                "Model is not ready. Call initializeAndTrain() or tryLoadModel() first.");
        }
    }
}
