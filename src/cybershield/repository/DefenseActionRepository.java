package cybershield.repository;

import cybershield.database.DatabaseConnection;
import cybershield.database.DatabaseException;
import cybershield.defense.DefenseActionType;
import cybershield.defense.DefenseResult;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

/**
 * DefenseActionRepository — Repository for defense_actions table.
 */
public class DefenseActionRepository {

    private final DatabaseConnection dbConn;

    public DefenseActionRepository() {
        this.dbConn = DatabaseConnection.getInstance();
    }

    public void insertAction(DefenseResult result, String incidentId) throws DatabaseException {
        String sql = "INSERT INTO defense_actions (action_id, alert_id, incident_id, action_type, target_identifier, action_result, explanation, execution_time) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = dbConn.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, result.getActionId());
            ps.setString(2, (result.getAlertId() == null || result.getAlertId().equals("N/A")) ? null : result.getAlertId());
            ps.setString(3, incidentId);
            ps.setString(4, result.getActionType().name());
            ps.setString(5, result.getTargetId());
            ps.setString(6, result.isSuccess() ? "SUCCESS" : "FAILED");
            ps.setString(7, result.getResultDescription());
            ps.setTimestamp(8, Timestamp.from(result.getTimestamp()));

            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("Failed to insert defense action: " + result.getActionId(), e);
        }
    }

    public List<DefenseResult> findRecent(int limit) throws DatabaseException {
        List<DefenseResult> list = new ArrayList<>();
        String sql = "SELECT action_id, alert_id, action_type, target_identifier, action_result, explanation, execution_time " +
                     "FROM defense_actions ORDER BY execution_time DESC LIMIT ?";
        try (Connection conn = dbConn.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String id = rs.getString("action_id");
                    String alertId = rs.getString("alert_id");
                    DefenseActionType type = DefenseActionType.valueOf(rs.getString("action_type"));
                    String target = rs.getString("target_identifier");
                    boolean success = "SUCCESS".equalsIgnoreCase(rs.getString("action_result"));
                    String desc = rs.getString("explanation");
                    Timestamp ts = rs.getTimestamp("execution_time");

                    list.add(new DefenseResult(id, type, alertId, target, success, desc, ts.toInstant(), null));
                }
            }
        } catch (SQLException e) {
            throw new DatabaseException("Failed to query defense actions", e);
        }
        return list;
    }

    public int countSuccessfulActions() throws DatabaseException {
        String sql = "SELECT COUNT(*) FROM defense_actions WHERE action_result = 'SUCCESS'";
        try (Connection conn = dbConn.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) return rs.getInt(1);
        } catch (SQLException e) {
            throw new DatabaseException("Failed to count successful defense actions", e);
        }
        return 0;
    }
}
