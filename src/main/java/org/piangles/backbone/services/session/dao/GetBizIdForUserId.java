package org.piangles.backbone.services.session.dao;

import org.apache.commons.lang3.StringUtils;
import org.piangles.core.dao.DAOException;

public class GetBizIdForUserId {

    private final SessionManagementDAO cacheDao;
    private final RdbmsDAO rdbmsDao;

    public GetBizIdForUserId(SessionManagementDAO cacheDao, RdbmsDAO rdbmsDao) {
        this.cacheDao = cacheDao;
        this.rdbmsDao = rdbmsDao;
    }

    public String apply(String userId) throws DAOException {
        String bizId = null;

        bizId = cacheDao.getBizId(userId);

        if (StringUtils.isEmpty(bizId)) {
            bizId = rdbmsDao.getBizIdFromUserId(userId);
            cacheDao.putUserIdBizId(userId, bizId);
        }

        return bizId;

    }
}
