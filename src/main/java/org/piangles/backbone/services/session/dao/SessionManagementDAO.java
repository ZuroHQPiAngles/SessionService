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

import org.piangles.backbone.services.session.SessionDetails;
import org.piangles.core.dao.DAOException;

public interface SessionManagementDAO
{
	public void storeSessionDetails(SessionDetails sessionDetails) throws DAOException;
	
	public SessionDetails getSessionDetails(String userId, String sessionId) throws DAOException;
	
	public List<SessionDetails> getAllSessionDetails(String userId) throws DAOException;
	
	//Remove from all caches for this user and this sessionId
	public void removeSessionDetails(String userId, String sessionId) throws DAOException;
	
	public void markForRemoveSessionDetails(String userId, String sessionId) throws DAOException;
	
	//Returns true if session exists else false and if it exists will update the lastAccessedTS
	public boolean isValid(String userId, String sessionId, String bizId) throws DAOException;
	
	//Touch lastAccessed if session is valid
	public void updateLastAccessed(String userId, String sessionId) throws DAOException;
	
	public void updateAuthenticationState(String userId, String sessionId, String authenticationState) throws DAOException;
	
	public int getExistingValidSessionCount(String userId) throws DAOException;

	String getBizId(String userId) throws DAOException;

	void putUserIdBizId(String userId, String bizId) throws DAOException;
}
