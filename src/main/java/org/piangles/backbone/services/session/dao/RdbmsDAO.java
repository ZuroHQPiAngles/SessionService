package org.piangles.backbone.services.session.dao;

import org.piangles.core.dao.DAOException;

public interface RdbmsDAO {

    String getBizIdFromUserId(String userId) throws DAOException;


}
