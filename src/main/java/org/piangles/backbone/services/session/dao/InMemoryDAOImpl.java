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
import org.piangles.core.dao.DAOException;

public final class InMemoryDAOImpl extends AbstractSessionManagementDAO
{
	//Only one cache will have SessionDetails the rest just have a reference to SessionId
	private Map<String, SessionDetails> sessionIdMap = null;
	private Map<String, List<String>> userIdSessionMap = null;

	public InMemoryDAOImpl(long sessionTimeout, int markSessionTimeout) throws Exception
	{
		super(sessionTimeout, markSessionTimeout);
		sessionIdMap = new HashMap<>();
		userIdSessionMap = new HashMap<String, List<String>>();
	}
	
	@Override
	public synchronized void storeSessionDetails(SessionDetails sessionDetails) throws DAOException
	{
		//Store in the userMap the sessionId
		List<String> sessionIds = userIdSessionMap.get(sessionDetails.getUserId()); 
		if (sessionIds == null)
		{
			sessionIds = new ArrayList<String>();
			userIdSessionMap.put(sessionDetails.getUserId(), sessionIds);
		}

		//Store the session details
		sessionIdMap.put(sessionDetails.getSessionId(), sessionDetails);
		sessionIds.add(sessionDetails.getSessionId());
	}

	@Override
	public synchronized void removeSessionDetails(String userId, String sessionId) throws DAOException
	{
		List<String> sessionIds = userIdSessionMap.get(userId);
		if (sessionIds != null)
		{
			sessionIds.remove(sessionId);
			sessionIdMap.remove(sessionId);
		}
	}
	
	@Override
	public void markForRemoveSessionDetails(String userId, String sessionId) throws DAOException
	{
		//TODO Add Timer to this userId and sessionId combination and remove it.
	}

	@Override
	public synchronized void updateLastAccessed(String userId, String sessionId) throws DAOException
	{
		SessionDetails sessionDetails = getSessionDetailsIfValidById(userId, sessionId, null);
		if (sessionDetails != null)
		{
			sessionDetails.touch();
		}
	}

	@Override
	public void updateAuthenticationState(String userId, String sessionId, String authenticationState) throws DAOException
	{
		SessionDetails sessionDetails = getSessionDetailsIfValidById(userId, sessionId, null);
		if (sessionDetails != null)
		{
			SessionDetails newSessionDetails = new SessionDetails(userId, null, sessionId,
																	authenticationState, 
																	sessionDetails.getInactivityExpiryTimeInSeconds(), 
																	sessionDetails.getCreatedTS(), sessionDetails.getLastAccessedTS());
			sessionIdMap.put(sessionDetails.getSessionId(), newSessionDetails);
		}
	}

	@Override
	public String getBizId(String userId) throws DAOException {
		return null;
	}

	@Override
	public void putUserIdBizId(String userId, String bizId) throws DAOException {

	}

	@Override
	public void storeExternalSessionDetails(ExternalUserSessionDetails sessionDetails) throws DAOException {

	}

	@Override
	protected synchronized List<String> getAllUserSessionIds(String userId) throws DAOException
	{
		return userIdSessionMap.get(userId);
	}

	@Override
	public synchronized SessionDetails getSessionDetails(String userId, String sessionId) throws DAOException
	{
		return sessionIdMap.get(sessionId);
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
	protected synchronized void removeAllExpiredSessionDetails(String userId) throws DAOException
	{
		List<String> validSessionIds = new ArrayList<String>();
		List<String> sessionIds = userIdSessionMap.get(userId);
		if (sessionIds != null)
		{
			for (String sessionId : sessionIds)
			{
				SessionDetails sessionDetails = sessionIdMap.get(sessionId);
				
				if (!isSessionValid(sessionDetails.getLastAccessedTS()))
				{
					sessionIdMap.remove(sessionId);
				}
				else
				{
					validSessionIds.add(sessionId);
				}
			}
			userIdSessionMap.put(userId, validSessionIds);
		}
	}
}
