package cybershield.database;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

/**
 * DatabaseConnection — Manages JDBC connection lifecycle and configuration loading.
 *
 * Implements:
 *   - Singleton pattern for centralized database configuration.
 *   - Environment variable overrides (CYBERSHIELD_DB_URL, CYBERSHIELD_DB_USER, CYBERSHIELD_DB_PASSWORD).
 *   - External configuration fallback (config/db.properties).
 *   - Graceful offline detection without fatal application crashes.
 */
public class DatabaseConnection {

    private static volatile DatabaseConnection instance;

    private String url;
    private String user;
    private String password;
    private String driver;
    private boolean initialized = false;
    private boolean connectionAvailable = false;

    private DatabaseConnection() {
        loadConfiguration();
    }

    public static DatabaseConnection getInstance() {
        if (instance == null) {
            synchronized (DatabaseConnection.class) {
                if (instance == null) {
                    instance = new DatabaseConnection();
                }
            }
        }
        return instance;
    }

    /**
     * Loads database properties from external config or environment variables.
     */
    public synchronized void loadConfiguration() {
        Properties props = new Properties();

        // 1. Default fallback settings
        this.driver = "com.mysql.cj.jdbc.Driver";
        this.url = "jdbc:mysql://localhost:3306/cybershield_arena?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC&createDatabaseIfNotExist=true";
        this.user = "root";
        this.password = "";

        // 2. Try loading from external config/db.properties file
        File configFile = new File("config/db.properties");
        if (configFile.exists()) {
            try (InputStream in = new FileInputStream(configFile)) {
                props.load(in);
                if (props.getProperty("db.driver") != null) driver = props.getProperty("db.driver").trim();
                if (props.getProperty("db.url") != null) url = props.getProperty("db.url").trim();
                if (props.getProperty("db.user") != null) user = props.getProperty("db.user").trim();
                if (props.getProperty("db.password") != null) password = props.getProperty("db.password").trim();
            } catch (Exception e) {
                System.err.println("[DatabaseConnection] Warning: Could not read config/db.properties: " + e.getMessage());
            }
        }

        // 3. Environment variables take highest precedence
        String envUrl = System.getenv("CYBERSHIELD_DB_URL");
        String envUser = System.getenv("CYBERSHIELD_DB_USER");
        String envPass = System.getenv("CYBERSHIELD_DB_PASSWORD");

        if (envUrl != null && !envUrl.isBlank()) this.url = envUrl;
        if (envUser != null && !envUser.isBlank()) this.user = envUser;
        if (envPass != null) this.password = envPass;

        // Verify driver class
        try {
            Class.forName(driver);
            this.initialized = true;
        } catch (ClassNotFoundException e) {
            this.initialized = false;
            System.err.println("[DatabaseConnection] MySQL Driver not found on classpath: " + driver);
        }

        testConnection();
    }

    /**
     * Tests if the MySQL database is reachable.
     */
    public boolean testConnection() {
        if (!initialized) {
            connectionAvailable = false;
            return false;
        }
        try (Connection conn = DriverManager.getConnection(url, user, password)) {
            connectionAvailable = (conn != null && !conn.isClosed());
            return connectionAvailable;
        } catch (SQLException e) {
            connectionAvailable = false;
            return false;
        }
    }

    /**
     * Obtains an active Connection instance.
     * Callers must manage lifecycle using try-with-resources.
     *
     * @return java.sql.Connection
     * @throws DatabaseException if connection cannot be established
     */
    public Connection getConnection() throws DatabaseException {
        if (!initialized) {
            throw new DatabaseException("DB_INIT_ERROR", "JDBC Driver is not initialized", null);
        }
        try {
            return DriverManager.getConnection(url, user, password);
        } catch (SQLException e) {
            this.connectionAvailable = false;
            throw new DatabaseException("DB_CONN_ERROR", "Failed to connect to MySQL database at " + url + ": " + e.getMessage(), e);
        }
    }

    public boolean isConnectionAvailable() {
        return connectionAvailable;
    }

    public String getUrl() {
        return url;
    }

    public String getUser() {
        return user;
    }

    public void setCredentials(String url, String user, String password) {
        this.url = url;
        this.user = user;
        this.password = password;
        testConnection();
    }
}
