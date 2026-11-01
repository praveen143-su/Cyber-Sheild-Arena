package cybershield.ml;

import java.time.Instant;

/**
 * ThreatPrediction — CyberShield Arena Phase 5
 *
 * OOP Concepts demonstrated:
 *   - Encapsulation  : All fields are private and final — the object cannot change once created.
 *   - Value Object   : Two predictions are the same if they contain the same data.
 *   - Separation of  : This class holds only the result of one prediction. It is completely
 *     Concerns         separate from the original SecurityEvent and from the model internals.
 *
 * IMPORTANT: confidenceScore is the model's class probability — the fraction of training
 * paths in the Decision Tree that voted for this class.  It is NOT a probability that an
 * actual attack has occurred in the real world.  A high score means the model is internally
 * consistent, not that the threat is definitively real.
 */
public class ThreatPrediction {

    private final String eventId;
    private final PredictionClass predictedClass;
    private final double confidenceScore;   // model probability [0.0 – 1.0], NOT real-world probability
    private final String modelId;
    private final Instant predictionTimestamp;
    private final String featureSummary;    // human-readable description of the feature values used

    /**
     * Creates a new ThreatPrediction.
     *
     * @param eventId         ID of the SecurityEvent that was classified
     * @param predictedClass  the class chosen by the model (NORMAL or SUSPICIOUS)
     * @param confidenceScore the model's own probability score for the chosen class [0.0 – 1.0]
     * @param modelId         name/version of the model that produced this prediction
     * @param featureSummary  short description of the features the model saw
     */
    public ThreatPrediction(String eventId, PredictionClass predictedClass,
                            double confidenceScore, String modelId, String featureSummary) {
        if (eventId == null || eventId.isBlank())
            throw new IllegalArgumentException("Event ID must not be blank.");
        if (predictedClass == null)
            throw new IllegalArgumentException("Predicted class must not be null.");
        if (confidenceScore < 0.0 || confidenceScore > 1.0)
            throw new IllegalArgumentException(
                "Confidence score must be between 0.0 and 1.0 (got " + confidenceScore + ").");
        if (modelId == null || modelId.isBlank())
            throw new IllegalArgumentException("Model ID must not be blank.");

        this.eventId            = eventId.trim();
        this.predictedClass     = predictedClass;
        this.confidenceScore    = confidenceScore;
        this.modelId            = modelId.trim();
        this.predictionTimestamp = Instant.now();
        this.featureSummary     = (featureSummary != null) ? featureSummary.trim() : "N/A";
    }

    // ---------------------------------------------------------------
    // Getters
    // ---------------------------------------------------------------

    public String getEventId()               { return eventId; }
    public PredictionClass getPredictedClass() { return predictedClass; }
    public double getConfidenceScore()        { return confidenceScore; }
    public String getModelId()               { return modelId; }
    public Instant getPredictionTimestamp()  { return predictionTimestamp; }
    public String getFeatureSummary()        { return featureSummary; }

    @Override
    public String toString() {
        return String.format("[%s] Event=%-10s | Class=%-10s | Confidence=%5.1f%% | Model=%s",
                predictionTimestamp, eventId, predictedClass.name(),
                confidenceScore * 100, modelId);
    }
}
