/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
 
 
package org.piangles.backbone.services.session.dao;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.piangles.backbone.services.session.ExternalUserSessionDetails;
import org.piangles.backbone.services.session.SessionDetails;
import org.piangles.backbone.services.session.SessionManagementService;
import org.piangles.core.dao.DAOException;
import org.piangles.core.resources.RedisCache;
import org.piangles.core.resources.ResourceException;
import org.piangles.core.resources.ResourceManager;
import org.piangles.core.util.central.CentralConfigProvider;

public final class DistributedCacheDAOImpl extends AbstractSessionManagementDAO
{
	private static final String REDIS_USER2SESSION_ID = "user:%s:session:id";
	private static final String REDIS_USER2SESSION_DETAILS = "user:%s:session:details:%s";
	
	private static final String USER_ID = "UserId";
	private static final String SESSION_ID = "SessionId";
	private static final String AUTHENTICATION_STATE = "authenticationState";
	private static final String CREATED_TS = "CreatedTS";
	private static final String LAST_ACCESSED_TS = "LastAccessedTS";
	private static final String BIZ_ID = "BizId";
	private static final String EXTERNAL_LINK_UUID = "ExternalLinkUUID";
	private static final String REFRESH_TOKEN = "RefreshToken";
	private static final String INVOICE_ID = "InvoiceId";


	/**
	 * The reason we are using Redis Lists and Map for saving Session related information
	 * is : SesssionManagementService allows for a user to have multiple sessions. So given
	 * a User we need to identify all the sessions, hence the User->SessionId is stored is a List.
	 * And the most efficient way to save SessionDetails is to break it down into NV Paid Vs
	 * saving it as JSON Objects. 
	 * 
	 * Saving it as JSON gives the additional challenege of having to deseralize the entire JSON Object 
	 * and specifically update LastAccessedTS and put it back into Cache.
	 * 
	 */
	private RedisCache redisCache = null;
	
	public DistributedCacheDAOImpl(long sessionTimeout, int markSessionTimeout) throws Exception
	{
		super(sessionTimeout, markSessionTimeout);
		redisCache = ResourceManager.getInstance().getRedisCache(new CentralConfigProvider(SessionManagementService.NAME, SessionManagementService.NAME));
	}
	
	@Override
	public void storeSessionDetails(SessionDetails sessionDetails) throws DAOException
	{
		try
		{
			redisCache.execute((jedis) -> {
				jedis.lpush(createUser2SessionIdKey(sessionDetails.getUserId()), sessionDetails.getSessionId());
				jedis.hmset(createUser2SessionDetailsKey(sessionDetails.getUserId(), sessionDetails.getSessionId()), createMap(sessionDetails));
				return null;
			});
		}
		catch (ResourceException e)
		{
			throw new DAOException(e);
		}
	}

	@Override
	public void removeSessionDetails(String userId, String sessionId) throws DAOException
	{
		try
		{
			redisCache.execute((jedis) -> {
				jedis.lrem(createUser2SessionIdKey(userId), 1, sessionId);
				jedis.del(createUser2SessionDetailsKey(userId, sessionId));
				return null;
			});
		}
		catch (ResourceException e)
		{
			throw new DAOException(e);
		}
	}

	@Override
	public void markForRemoveSessionDetails(String userId, String sessionId) throws DAOException
	{
		try
		{
			redisCache.execute((jedis) -> {
				jedis.expire(createUser2SessionDetailsKey(userId, sessionId), getMarkSessionTimeout());
				return null;
			});
		}
		catch (ResourceException e)
		{
			throw new DAOException(e);
		}
	}
	
	@Override
	public void updateLastAccessed(String userId, String sessionId) throws DAOException
	{
		try
		{
			redisCache.execute((jedis) -> {
				String key = createUser2SessionDetailsKey(userId, sessionId);
				jedis.hset(key, LAST_ACCESSED_TS, "" + System.currentTimeMillis());
				jedis.persist(key);//Remove Expiry in case it was set.
				return null;
			});
		}
		catch (ResourceException e)
		{
			throw new DAOException(e);
		}
	}

	@Override
	public void updateAuthenticationState(String userId, String sessionId, String authenticationState) throws DAOException
	{
		try
		{
			redisCache.execute((jedis) -> {
				String key = createUser2SessionDetailsKey(userId, sessionId);
				jedis.hset(key, AUTHENTICATION_STATE, authenticationState);
				jedis.persist(key);//Remove Expiry in case it was set.
				return null;
			});
		}
		catch (ResourceException e)
		{
			throw new DAOException(e);
		}
	}

	@Override
	public String getBizId(String userId) throws DAOException {
        try
		{
            return redisCache.execute((jedis)-> jedis.get(userId));
        }
		catch (ResourceException e)
		{
            throw new DAOException(e);
        }
    }

	@Override
	public void putUserIdBizId(String userId, String bizId) throws DAOException {
		try
		{
			redisCache.execute((jedis)-> {
				jedis.set(userId, bizId);
				return null;
			});
		}
		catch (ResourceException e)
		{
			throw new DAOException(e);
		}
	}

	@Override
	public void storeExternalSessionDetails(ExternalUserSessionDetails sessionDetails) throws DAOException {
		try
		{
			redisCache.execute((jedis) -> {
				jedis.lpush(createUser2SessionIdKey(sessionDetails.getExternalUserId()), sessionDetails.getSessionId());
				jedis.hmset(createUser2SessionDetailsKey(sessionDetails.getExternalUserId(), sessionDetails.getSessionId()), createExternalSessionDetailsMap(sessionDetails));
				return null;
			});
		}
		catch (ResourceException e)
		{
			throw new DAOException(e);
		}
	}

	private Map<String, String> createExternalSessionDetailsMap(ExternalUserSessionDetails sessionDetails) {
		Map<String, String> map = new HashMap<>();
		map.put(USER_ID, sessionDetails.getExternalUserId());
		map.put(SESSION_ID, sessionDetails.getSessionId());
		map.put(AUTHENTICATION_STATE, sessionDetails.getAuthenticationState());
		map.put(CREATED_TS, "" + sessionDetails.getCreatedTS());
		map.put(LAST_ACCESSED_TS, "" + sessionDetails.getLastAccessedTS());
		map.put(BIZ_ID, sessionDetails.getExternalBizId());
		map.put(INVOICE_ID, sessionDetails.getInvoiceId());
		map.put(REFRESH_TOKEN, sessionDetails.getRefreshToken());
		map.put(EXTERNAL_LINK_UUID, sessionDetails.getUuid());

		return map;
	}

	@Override
	protected List<String> getAllUserSessionIds(String userId) throws DAOException
	{
		List<String> sessionIds;
		try
		{
			sessionIds = redisCache.execute((jedis) -> {
				 return jedis.lrange(createUser2SessionIdKey(userId), 0, 100);
			});
		}
		catch (ResourceException e)
		{
			throw new DAOException(e);
		}

		return sessionIds;
	}

	@Override
	public SessionDetails getSessionDetails(String userId, String sessionId) throws DAOException
	{
		SessionDetails sessionDetails;
		try
		{
			sessionDetails = redisCache.execute((jedis) -> {
				Map<String, String> map = jedis.hgetAll(createUser2SessionDetailsKey(userId, sessionId));
				SessionDetails sd = createSessionDetails(map);
				return sd;
			});
		}
		catch (ResourceException e)
		{
			throw new DAOException(e);
		}
		return sessionDetails;
	}
	

	@Override
	public List<SessionDetails> getAllSessionDetails(String userId) throws DAOException
	{
		List<SessionDetails> userSessionDetails = new ArrayList<>();
		
		List<String> userSessionIds = getAllUserSessionIds(userId);
		
		if(!userSessionIds.isEmpty() && userSessionIds != null)
		{
			for(String sessionId : userSessionIds)
			{
				SessionDetails sessionDetails = getSessionDetails(userId, sessionId);
				
				userSessionDetails.add(sessionDetails);
			}
		}

		return userSessionDetails;
	}
	
	@Override
	protected void removeAllExpiredSessionDetails(String userId) throws DAOException
	{
		List<String> sessionIds = getAllUserSessionIds(userId);
		if (sessionIds != null)
		{
			try
			{
				redisCache.execute((jedis) -> {
					for (String sessionId : sessionIds)
					{
						SessionDetails sessionDetails = createSessionDetails(jedis.hgetAll(createUser2SessionDetailsKey(userId, sessionId)));
						
						if (sessionDetails == null)
						{
							jedis.lrem(createUser2SessionIdKey(userId), 1, sessionId);
						}
						else if (sessionDetails != null && !isSessionValid(sessionDetails.getLastAccessedTS()))
						{
							jedis.lrem(createUser2SessionIdKey(userId), 1, sessionId);
							jedis.del(createUser2SessionDetailsKey(userId, sessionId));
						}
					}
					return null;
				});
			}
			catch (ResourceException e)
			{
				throw new DAOException(e);
			}
		}
	}
	
	private Map<String, String> createMap(SessionDetails sessionDetails)
	{
		Map<String, String> map = new HashMap<>();
		map.put(USER_ID, sessionDetails.getUserId());
		map.put(SESSION_ID, sessionDetails.getSessionId());
		map.put(AUTHENTICATION_STATE, sessionDetails.getAuthenticationState());
		map.put(CREATED_TS, "" + sessionDetails.getCreatedTS());
		map.put(LAST_ACCESSED_TS, "" + sessionDetails.getLastAccessedTS());
		map.put(BIZ_ID, sessionDetails.getBizId());
		
		return map;
	}
	
	private SessionDetails createSessionDetails(Map<String, String> map)
	{
		SessionDetails sessionDetails = null;
		if (map != null && !map.isEmpty())
		{
			String userId = map.get(USER_ID);
			String sessionId = map.get(SESSION_ID);
			String authenticationState = map.get(AUTHENTICATION_STATE);
			long createdTS = Long.parseLong(map.get(CREATED_TS));
			long lastAccessedTS = Long.parseLong(map.get(LAST_ACCESSED_TS));
			String bizId = map.get(BIZ_ID);
			
			sessionDetails = new SessionDetails(userId, bizId, sessionId, authenticationState, getSessionTimeout(), createdTS, lastAccessedTS);
		}
		return sessionDetails;
	}
	
	private String createUser2SessionIdKey(String userId)
	{
		return String.format(REDIS_USER2SESSION_ID, userId);
	}
	
	private String createUser2SessionDetailsKey(String userId, String sessionId)
	{
		return String.format(REDIS_USER2SESSION_DETAILS, userId, sessionId);
	}
}
