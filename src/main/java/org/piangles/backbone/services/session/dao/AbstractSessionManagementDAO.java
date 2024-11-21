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

import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.piangles.backbone.services.session.SessionDetails;
import org.piangles.core.dao.DAOException;

public abstract class AbstractSessionManagementDAO implements SessionManagementDAO
{
	private static final String POST_AUTHENTICATION_STATE = "PostAuthentication";
	private long sessionTimeout;
	private int markSessionTimeout;

	public AbstractSessionManagementDAO(long sessionTimeout, int markSessionTimeout)
	{
		this.sessionTimeout = sessionTimeout;
		this.markSessionTimeout = markSessionTimeout;
	}
	
	@Override
	public final boolean isValid(String userId, String sessionId, String bizId) throws DAOException
	{
		boolean valid = false;
		SessionDetails sessionDetails = getSessionDetailsIfValidById(userId, sessionId, bizId);
		if (sessionDetails != null)
		{
			valid = true;
		}
		
		return valid;
	}

	@Override
	public final int getExistingValidSessionCount(String userId, String bizId) throws DAOException
	{
		int existingSessionCount = 0;
		
		removeAllExpiredSessionDetails(userId);
		
		List<String> allUserSessionIds = getAllUserSessionIds(userId);

		if (allUserSessionIds != null)
		{
			 for (String sessionId : allUserSessionIds)
			 {
				 SessionDetails sessionDetails = getSessionDetailsIfValidById(userId, sessionId, bizId);
				 if (sessionDetails != null && POST_AUTHENTICATION_STATE.equals(sessionDetails.getAuthenticationState()))
				 {
					 existingSessionCount++;
				 }
			 }
		}
		
		return existingSessionCount;
	}
	
	protected final SessionDetails getSessionDetailsIfValidById(String userId, String sessionId, String bizId) throws DAOException
	{
		SessionDetails sessionDetails = getSessionDetails(userId, sessionId);
		if (sessionDetails != null && sessionDetails.getUserId().equals(userId))
		{
			if (!isSessionValid(sessionDetails.getLastAccessedTS()))
			{
				sessionDetails = null;
			}
			else if (!StringUtils.isEmpty(sessionDetails.getBizId()) && !sessionDetails.getBizId().equals(bizId))
			{
				sessionDetails = null;
			}
		}
		else
		{
			sessionDetails = null;
		}
		return sessionDetails;
	}


	protected final boolean isSessionValid(long lastAccessedTS)
	{
		return ((System.currentTimeMillis() - lastAccessedTS) < (sessionTimeout * 1000));
	}
	
	protected final long getSessionTimeout()
	{
		return sessionTimeout;
	}

	protected final int getMarkSessionTimeout()
	{
		return markSessionTimeout;
	}

	protected abstract List<String> getAllUserSessionIds(String userId) throws DAOException;
	//Remove from all caches expired sessions for this User
	protected abstract void removeAllExpiredSessionDetails(String userId) throws DAOException;
}
