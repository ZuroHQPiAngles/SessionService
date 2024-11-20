package org.piangles.backbone.services.session.dao;

import org.piangles.backbone.services.session.SessionManagementService;
import org.piangles.core.dao.DAOException;
import org.piangles.core.resources.RDBMSDataStore;
import org.piangles.core.resources.ResourceException;
import org.piangles.core.resources.ResourceManager;
import org.piangles.core.util.central.CentralConfigProvider;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class RdbmsDAOImpl implements RdbmsDAO {

    private static final String COMPONENT_ID = "PostgresSessionManagementService";
    private static final String COMPONENT_NAME = "SessionManagementDAO";
    private RDBMSDataStore rdbmsDataStore;

    public RdbmsDAOImpl() throws ResourceException {
        rdbmsDataStore = ResourceManager.getInstance().getRDBMSDataStore(
                new CentralConfigProvider(COMPONENT_ID, COMPONENT_NAME)
        );
    }

    @Override
    public String getBizIdFromUserId(String userId) throws DAOException {

        try(PreparedStatement stmt = rdbmsDataStore.getConnection().prepareCall("{call biz.get_business_profiles(?, ?)}"))
        {
            stmt.setString(1, userId);
            stmt.setString(2, null);
            stmt.executeQuery();
            ResultSet rs = stmt.getResultSet();
            if(rs.next()) {
                return rs.getString("biz_id");
            }
            else
            {
                throw new DAOException("Unable to retrieve business profile with userId: " + userId);
            }
        }
        catch (SQLException e)
        {
            throw new DAOException(e.getMessage(), e);
        }

    }
}
