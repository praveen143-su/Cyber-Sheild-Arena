package cybershield.ml;

import cybershield.security.SecurityEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * MLDetectionEngine — CyberShield Arena Phase 5
 *
 * OOP Concepts demonstrated:
 *   - Facade Pattern     : Hides the feature-extraction + model steps behind a single analyzeEvent() call.
 *   - Separation of Concerns : ML detection lives here; rule-based detection stays in
 *                               RuleBasedDetectionEngine. Neither class knows about the other.
 *   - Fault Tolerance    : If the model throws an exception, a fallback prediction is returned so
 *                           the rest of the monitoring pipeline continues without crashing.
 *
 * ─── How it fits into the pipeline ──────────────────────────────────────────
 *
 *   SimulationEngine → SecurityEvent
 *        │
 *        ▼
 *   MLDetectionEngine.analyzeEvent(event)
 *        │
 *        ├── MLFeatureExtractor.extractFeatures(event)   → double[]
 *        │
 *        └── ThreatDetectionModel.predict(eventId, features) → ThreatPrediction
 *
 * The engine stores a history of all predictions so DetectionComparison can
 * retrieve them later for analysis.
 */
public class MLDetectionEngine {

    private final ThreatDetectionModel model;
    private final MLFeatureExtractor featureExtractor;
    private final List<ThreatPrediction> predictionHistory;

    /**
     * Creates an MLDetectionEngine backed by the given trained model.
     *
     * @param model a trained ThreatDetectionModel (isTrained() must be true before analyzeEvent() is called)
     */
    public MLDetectionEngine(ThreatDetectionModel model) {
        if (model == null) {
            throw new IllegalArgumentException("ThreatDetectionModel must not be null.");
        }
        this.model             = model;
        this.featureExtractor  = new MLFeatureExtractor();
        this.predictionHistory = new ArrayList<>();
    }

    // ---------------------------------------------------------------
    // Analysis methods
    // ---------------------------------------------------------------

    /**
     * Analyses a single SecurityEvent and returns an ML ThreatPrediction.
     *
     * If the model fails for any reason (e.g. the feature values are out of range),
     * a fallback prediction of NORMAL with 0 % confidence is returned so the
     * monitoring pipeline does not crash.  The failure is logged to stderr.
     *
     * @param event the event to classify
     * @return ThreatPrediction — never null
     */
    public ThreatPrediction analyzeEvent(SecurityEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("SecurityEvent must not be null.");
        }
        try {
            double[] features = featureExtractor.extractFeatures(event);
            ThreatPrediction prediction = model.predict(event.getEventId(), features);
            predictionHistory.add(prediction);
            return prediction;
        } catch (Exception e) {
            System.err.printf("[MLDetectionEngine] Prediction failed for event %s: %s%n",
                    event.getEventId(), e.getMessage());
            // Fallback: assume NORMAL with 0 confidence — clearly marks a failed prediction
            ThreatPrediction fallback = new ThreatPrediction(
                    event.getEventId(),
                    PredictionClass.NORMAL,
                    0.0,
                    model.getModelId(),
                    "PREDICTION FAILED — fallback to NORMAL"
            );
            predictionHistory.add(fallback);
            return fallback;
        }
    }

    /**
     * Analyses a list of SecurityEvents in order and returns all predictions.
     *
     * @param events the events to classify
     * @return list of ThreatPredictions in the same order as the input list
     */
    public List<ThreatPrediction> analyzeEvents(List<SecurityEvent> events) {
        if (events == null) return Collections.emptyList();
        List<ThreatPrediction> results = new ArrayList<>();
        for (SecurityEvent event : events) {
            results.add(analyzeEvent(event));
        }
        return results;
    }

    // ---------------------------------------------------------------
    // History and stats
    // ---------------------------------------------------------------

    /**
     * Returns an unmodifiable view of all predictions made since this engine was created.
     */
    public List<ThreatPrediction> getPredictionHistory() {
        return Collections.unmodifiableList(predictionHistory);
    }

    /**
     * Counts how many predictions of the given class are in the history.
     *
     * @param targetClass the class to count
     * @return count of matching predictions
     */
    public long countPredictions(PredictionClass targetClass) {
        return predictionHistory.stream()
                .filter(p -> p.getPredictedClass() == targetClass)
                .count();
    }

    /** Returns the underlying ThreatDetectionModel. */
    public ThreatDetectionModel getModel() { return model; }
}
