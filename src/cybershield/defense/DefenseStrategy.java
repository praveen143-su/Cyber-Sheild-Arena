package cybershield.defense;

/**
 * DefenseStrategy — CyberShield Arena Phase 6
 *
 * OOP Concepts demonstrated:
 *   - Interface Contract : Defines an abstract polymorphic contract for all response strategies.
 *   - Strategy Pattern   : Allows different defensive behaviors (blocking, isolation, recovery)
 *                          to be selected and swapped at runtime without changing the invoker (DefenseAgent).
 *   - Open-Closed Principle: New defense mechanisms can be implemented by creating new strategy
 *                          classes without editing existing agent logic.
 *   - Pure Domain Logic  : Implementations do not write directly to console; they return
 *                          a structured DefenseResult for the monitoring and audit layers.
 */
public interface DefenseStrategy {

    /**
     * Executes the defensive response within the simulated network environment.
     *
     * @param context  simulation boundary providing virtual network and topology access
     * @param targetId identifier of the target node or connection
     * @param alertId  identifier of the triggering security alert (or null/N/A)
     * @param reason   justification for the action (e.g. policy rule or risk justification)
     * @return a structured DefenseResult detailing whether the action succeeded or failed
     */
    DefenseResult execute(DefenseContext context, String targetId, String alertId, String reason);

    /**
     * Returns the human-readable name of this defensive strategy.
     *
     * @return strategy name string
     */
    String getStrategyName();

    /**
     * Returns the DefenseActionType associated with this strategy.
     *
     * @return action type enum
     */
    DefenseActionType getActionType();
}
