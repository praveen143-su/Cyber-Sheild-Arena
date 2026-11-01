package cybershield.ml;

import weka.core.Instances;

/**
 * ThreatDetectionModel — CyberShield Arena Phase 5
 *
 * OOP Concept: Interface / Strategy Pattern
 *
 * An interface defines a CONTRACT — it says what an object CAN DO,
 * not HOW it does it.  Any class that implements this interface promises
 * to provide all of these methods.
 *
 * Why an interface?
 *   Today we use a Decision Tree (J48).  In Phase 6 or later we might
 *   switch to a Random Forest or a Neural Network.  Because Main.java and
 *   MLDetectionEngine only talk to this interface, swapping the underlying
 *   algorithm requires zero changes to any other class.
 *
 * Weka's Instances is used here because the training data is always
 * a Weka dataset in this project.  If you wanted to hide Weka entirely
 * from the interface you would pass a plain double[][] matrix instead,
 * but that would reduce usability with Weka's built-in evaluator.
 */
public interface ThreatDetectionModel {

    /**
     * Trains the model on labelled data.
     * Must be called before predict().
     *
     * @param trainingData a Weka Instances object with the class attribute set
     * @throws Exception if training fails for any reason
     */
    void train(Instances trainingData) throws Exception;

    /**
     * Predicts the class of a single unseen event.
     *
     * @param eventId  the ID of the SecurityEvent (used for the result object only, not as a feature)
     * @param features numeric feature array in the same column order as training
     * @return a ThreatPrediction containing the class and the model's confidence score
     * @throws Exception if the prediction fails
     */
    ThreatPrediction predict(String eventId, double[] features) throws Exception;

    /**
     * Returns a unique identifier for this model and its version.
     * Useful for logging and comparing results from different models.
     */
    String getModelId();

    /**
     * Returns true if the model has been successfully trained and is ready to predict.
     */
    boolean isTrained();

    /**
     * Saves the trained model to a file so it can be reloaded without retraining.
     *
     * @param filePath destination file (e.g. "models/cybershield_dt.model")
     * @throws Exception if the file cannot be written
     */
    void saveModel(String filePath) throws Exception;

    /**
     * Loads a previously saved model from a file.
     * After a successful load, isTrained() returns true.
     *
     * @param filePath path to the saved model file
     * @throws Exception if the file is missing, corrupt, or uses an incompatible schema
     */
    void loadModel(String filePath) throws Exception;

    /**
     * Returns the Weka Instances header (schema only, no data rows) that was used
     * during training.  The header is needed by ModelEvaluator to construct test
     * instances that are compatible with the trained model.
     */
    Instances getTrainingDataHeader();
}
