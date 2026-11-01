package cybershield.ml;

/**
 * PredictionClass — CyberShield Arena Phase 5
 *
 * OOP Concept: Enum (Enumeration)
 * Purpose    : Defines the two possible outcomes of the ML threat-detection model.
 *
 * Think of this like a traffic light that only has two colours:
 *   NORMAL     — green: the event looks like everyday, benign network activity.
 *   SUSPICIOUS — red  : the event's features match patterns seen in attack scenarios.
 *
 * Using an enum instead of a plain String prevents typos (e.g. "suspisious")
 * and makes the code self-documenting and type-safe.
 */
public enum PredictionClass {

    NORMAL(
        "Normal Activity",
        "Event characteristics match typical benign network behaviour."
    ),
    SUSPICIOUS(
        "Suspicious Activity",
        "Event characteristics indicate potential malicious behaviour."
    );

    private final String displayLabel;
    private final String description;

    PredictionClass(String displayLabel, String description) {
        this.displayLabel = displayLabel;
        this.description  = description;
    }

    public String getDisplayLabel() { return displayLabel; }
    public String getDescription()  { return description;  }

    @Override
    public String toString() { return displayLabel; }
}
