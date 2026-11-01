package cybershield.database;

/**
 * DatabaseException — Custom exception representing database errors in CyberShield Arena.
 * Encapsulates SQL errors with meaningful, user-friendly messages for UI display.
 */
public class DatabaseException extends RuntimeException {

    private final String errorCode;

    public DatabaseException(String message) {
        super(message);
        this.errorCode = "DB_GENERAL_ERROR";
    }

    public DatabaseException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = "DB_SQL_ERROR";
    }

    public DatabaseException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
