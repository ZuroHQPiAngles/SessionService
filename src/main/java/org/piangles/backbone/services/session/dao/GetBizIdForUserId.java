package org.piangles.backbone.services.session.dao;

import org.apache.commons.lang3.StringUtils;
import org.piangles.backbone.services.Locator;
import org.piangles.backbone.services.logging.LoggingService;
import org.piangles.core.dao.DAOException;

public class GetBizIdForUserId {

    private final LoggingService logger = Locator.getInstance().getLoggingService();
    private final SessionManagementDAO cacheDao;
    private final RdbmsDAO rdbmsDao;

    public GetBizIdForUserId(SessionManagementDAO cacheDao, RdbmsDAO rdbmsDao) {
        this.cacheDao = cacheDao;
        this.rdbmsDao = rdbmsDao;
    }

    public String apply(String userId) throws DAOException {
        String bizId = null;

        bizId = cacheDao.getBizId(userId);
        logger.info("Fetched BizId: " + bizId + " from cache for userId: " + userId);

        if (StringUtils.isEmpty(bizId)) {
            logger.info("BizId: " + bizId + " not found in cache. Looking in DB.");
            bizId = rdbmsDao.getBizIdFromUserId(userId);
            logger.info("Fetched BizId: " + bizId + " from DB for userId: " + userId);
            cacheDao.putUserIdBizId(userId, bizId);
        }

        return bizId;

    }
}
