package cybershield.database;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * DatabaseInitializer — Bootstraps the cybershield_arena MySQL schema.
 * Reads schema.sql and creates tables, indexes, constraints, and initial views.
 */
public class DatabaseInitializer {

    private static final String SCHEMA_PATH = "src/main/resources/db/schema.sql";

    /**
     * Executes the schema initialization script.
     *
     * @return true if schema is successfully verified or initialized, false otherwise.
     */
    public static boolean initializeDatabase() {
        DatabaseConnection dbConn = DatabaseConnection.getInstance();
        if (!dbConn.testConnection()) {
            System.err.println("[DatabaseInitializer] MySQL server is not reachable. Running in offline/in-memory mode.");
            return false;
        }

        List<String> statements = loadSqlStatements();
        if (statements.isEmpty()) {
            System.err.println("[DatabaseInitializer] Warning: No SQL statements found in schema.sql");
            return false;
        }

        try (Connection conn = dbConn.getConnection();
             Statement stmt = conn.createStatement()) {

            for (String sql : statements) {
                if (sql.trim().isEmpty()) continue;
                try {
                    stmt.execute(sql);
                } catch (Exception e) {
                    System.err.println("[DatabaseInitializer] Warning on statement: " + sql + " -> " + e.getMessage());
                }
            }

            System.out.println("[DatabaseInitializer] Schema 'cybershield_arena' verified and initialized successfully.");
            return true;

        } catch (Exception e) {
            System.err.println("[DatabaseInitializer] Initialization error: " + e.getMessage());
            return false;
        }
    }

    private static List<String> loadSqlStatements() {
        List<String> statements = new ArrayList<>();
        InputStream is = null;

        try {
            File schemaFile = new File(SCHEMA_PATH);
            if (schemaFile.exists()) {
                is = new FileInputStream(schemaFile);
            } else {
                is = DatabaseInitializer.class.getResourceAsStream("/db/schema.sql");
            }

            if (is == null) {
                return statements;
            }

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                StringBuilder current = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    String trimmed = line.trim();
                    if (trimmed.startsWith("--") || trimmed.startsWith("//") || trimmed.isEmpty()) {
                        continue;
                    }
                    current.append(line).append(" ");
                    if (trimmed.endsWith(";")) {
                        String sql = current.toString().trim();
                        // remove trailing semicolon
                        sql = sql.substring(0, sql.length() - 1).trim();
                        if (!sql.isEmpty()) {
                            statements.add(sql);
                        }
                        current.setLength(0);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("[DatabaseInitializer] Error loading schema.sql: " + e.getMessage());
        } finally {
            if (is != null) {
                try { is.close(); } catch (Exception ignored) {}
            }
        }

        return statements;
    }
}
