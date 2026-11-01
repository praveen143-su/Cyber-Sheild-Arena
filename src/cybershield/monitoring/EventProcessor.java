package cybershield.monitoring;

import cybershield.security.SecurityEvent;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Queue;
import java.util.function.Consumer;

/**
 * EventProcessor — CyberShield Arena Phase 4
 *
 * OOP Concepts demonstrated:
 *   - Queue / FIFO Data Structure : Decouples event generation from downstream consumption.
 *   - Single Processing Guarantee : Polling ensures each event is processed exactly once per cycle.
 *   - Separation of Concerns      : Focuses purely on queuing and dispatching.
 */
public class EventProcessor {

    private final Queue<SecurityEvent> eventQueue = new ArrayDeque<>();
    private int totalProcessedCount = 0;

    public EventProcessor() {
        // Default constructor
    }

    /**
     * Enqueues a single event for processing.
     *
     * @param event the event to enqueue
     */
    public void enqueue(SecurityEvent event) {
        if (event != null) {
            eventQueue.offer(event);
        }
    }

    /**
     * Enqueues a collection of events for processing.
     *
     * @param events events to add to processing queue
     */
    public void enqueueAll(Collection<SecurityEvent> events) {
        if (events != null) {
            for (SecurityEvent ev : events) {
                if (ev != null) {
                    eventQueue.offer(ev);
                }
            }
        }
    }

    /**
     * Drains the queue and passes each event to the specified consumer.
     * Guarantees each event is polled exactly once and removed from pending.
     *
     * @param handler consumer executing detection or handling logic
     * @return count of processed events in this cycle
     */
    public int processAll(Consumer<SecurityEvent> handler) {
        if (handler == null) {
            throw new IllegalArgumentException("Event handler consumer cannot be null.");
        }

        int cycleCount = 0;
        while (!eventQueue.isEmpty()) {
            SecurityEvent event = eventQueue.poll();
            if (event != null) {
                handler.accept(event);
                cycleCount++;
                totalProcessedCount++;
            }
        }
        return cycleCount;
    }

    /**
     * Drains the queue and returns all pending events as a List.
     *
     * @return list of drained events
     */
    public List<SecurityEvent> drainAll() {
        List<SecurityEvent> drained = new ArrayList<>();
        while (!eventQueue.isEmpty()) {
            SecurityEvent ev = eventQueue.poll();
            if (ev != null) {
                drained.add(ev);
                totalProcessedCount++;
            }
        }
        return drained;
    }

    public int getPendingCount() {
        return eventQueue.size();
    }

    public int getTotalProcessedCount() {
        return totalProcessedCount;
    }

    public boolean isEmpty() {
        return eventQueue.isEmpty();
    }
}
