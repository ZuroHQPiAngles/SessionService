package org.piangles.backbone.services.session.dao;

import org.piangles.backbone.services.Locator;
import org.piangles.backbone.services.logging.LoggingService;
import org.piangles.core.dao.DAOException;
import org.piangles.core.resources.RDBMSDataStore;
import org.piangles.core.resources.ResourceException;
import org.piangles.core.resources.ResourceManager;
import org.piangles.core.util.central.CentralConfigProvider;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;

public class RdbmsDAOImpl implements RdbmsDAO {

    private static final String COMPONENT_ID = "PostgresSessionManagementService";
    private static final String COMPONENT_NAME = "SessionManagementDAO";
    private LoggingService logger;
    private RDBMSDataStore rdbmsDataStore;

    public RdbmsDAOImpl() throws ResourceException {
        logger = Locator.getInstance().getLoggingService();
        rdbmsDataStore = ResourceManager.getInstance().getRDBMSDataStore(
                new CentralConfigProvider(COMPONENT_ID, COMPONENT_NAME)
        );
    }

    @Override
    public String getBizIdFromUserId(String userId) throws DAOException {

        try(PreparedStatement stmt = rdbmsDataStore.getConnection().prepareCall("{call biz.get_business_profiles(?, ?)}"))
        {
            stmt.setString(1, userId);
            stmt.setNull(2, Types.VARCHAR);

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("biz_id");
                } else {
                    throw new DAOException("Not found business profile in DB with userId: " + userId);
                }
            }
        }
        catch (SQLException e)
        {
            logger.error("Error while retrieving business profile with userId: " + userId + " .Reason: " + e.getMessage());
            throw new DAOException(e);
        }

    }
}
