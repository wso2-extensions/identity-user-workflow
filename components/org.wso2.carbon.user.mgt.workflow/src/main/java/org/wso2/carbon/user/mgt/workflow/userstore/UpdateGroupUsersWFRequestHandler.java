/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.user.mgt.workflow.userstore;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.workflow.mgt.WorkflowManagementService;
import org.wso2.carbon.identity.workflow.mgt.bean.Entity;
import org.wso2.carbon.identity.workflow.mgt.exception.InternalWorkflowException;
import org.wso2.carbon.identity.workflow.mgt.exception.WorkflowException;
import org.wso2.carbon.identity.workflow.mgt.extension.AbstractWorkflowRequestHandler;
import org.wso2.carbon.identity.workflow.mgt.util.WorkflowDataType;
import org.wso2.carbon.identity.workflow.mgt.util.WorkflowRequestStatus;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.user.mgt.workflow.internal.IdentityWorkflowDataHolder;
import org.wso2.carbon.user.mgt.workflow.util.UserStoreWFConstants;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Update group users workflow request handler.
 */
public class UpdateGroupUsersWFRequestHandler extends AbstractWorkflowRequestHandler {

    private static final String FRIENDLY_NAME = "Update Users Of Group";
    private static final String FRIENDLY_DESCRIPTION = "Triggered when users are added to/removed from a group.";

    private static final String GROUP_NAME = "Group Name";
    private static final String USER_STORE_DOMAIN = "User Store Domain";
    private static final String DELETED_USER_LIST = "Users to be Deleted";
    private static final String NEW_USER_LIST = "Users to be Added";

    private static final Map<String, String> PARAM_DEFINITION;
    private static final Log log = LogFactory.getLog(UpdateGroupUsersWFRequestHandler.class);

    static {
        PARAM_DEFINITION = new LinkedHashMap<>();
        PARAM_DEFINITION.put(GROUP_NAME, WorkflowDataType.STRING_TYPE);
        PARAM_DEFINITION.put(USER_STORE_DOMAIN, WorkflowDataType.STRING_TYPE);
        PARAM_DEFINITION.put(DELETED_USER_LIST, WorkflowDataType.STRING_LIST_TYPE);
        PARAM_DEFINITION.put(NEW_USER_LIST, WorkflowDataType.STRING_LIST_TYPE);
    }

    /**
     * Start workflow for updating users of a group.
     *
     * @param userStoreDomain User store domain.
     * @param groupName       Name of the group.
     * @param deletedUsers    Users to be removed from the group.
     * @param newUsers        Users to be added to the group.
     * @return True if the operation should proceed, false if a workflow is pending.
     * @throws WorkflowException If an error occurs while starting the workflow.
     */
    public boolean startUpdateGroupUsersFlow(String userStoreDomain, String groupName, String[] deletedUsers,
                                             String[] newUsers) throws WorkflowException {

        WorkflowManagementService workflowService = IdentityWorkflowDataHolder.getInstance().getWorkflowService();

        if (deletedUsers == null) {
            deletedUsers = new String[0];
        }
        if (newUsers == null) {
            newUsers = new String[0];
        }
        int tenant = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        String fullyQualifiedName = UserCoreUtil.addDomainToName(groupName, userStoreDomain);
        Map<String, Object> wfParams = new HashMap<>();
        Map<String, Object> nonWfParams = new HashMap<>();
        wfParams.put(GROUP_NAME, groupName);
        wfParams.put(USER_STORE_DOMAIN, userStoreDomain);
        wfParams.put(DELETED_USER_LIST, Arrays.asList(deletedUsers));
        wfParams.put(NEW_USER_LIST, Arrays.asList(newUsers));
        String uuid = UUID.randomUUID().toString();
        Entity[] entities = new Entity[deletedUsers.length + newUsers.length + 1];
        entities[0] = new Entity(fullyQualifiedName, UserStoreWFConstants.ENTITY_TYPE_GROUP, tenant);
        for (int i = 0; i < newUsers.length; i++) {
            fullyQualifiedName = UserCoreUtil.addDomainToName(newUsers[i], userStoreDomain);
            entities[i + 1] = new Entity(fullyQualifiedName, UserStoreWFConstants.ENTITY_TYPE_USER, tenant);
        }
        for (int i = 0; i < deletedUsers.length; i++) {
            fullyQualifiedName = UserCoreUtil.addDomainToName(deletedUsers[i], userStoreDomain);
            entities[i + newUsers.length + 1] = new Entity(fullyQualifiedName, UserStoreWFConstants.ENTITY_TYPE_USER,
                    tenant);
        }
        if (workflowService.isEventAssociated(UserStoreWFConstants.UPDATE_GROUP_USERS_EVENT) && !Boolean.TRUE
                .equals(getWorkFlowCompleted()) && !isValidOperation(entities)) {
            throw new WorkflowException("Operation is not valid.");
        }
        boolean state = startWorkFlow(wfParams, nonWfParams, uuid).getExecutorResultState().state();

        // WF_REQUEST_ENTITY_RELATIONSHIP table has foreign key to WF_REQUEST, so need to run this after WF_REQUEST is
        // updated.
        if (!Boolean.TRUE.equals(getWorkFlowCompleted()) && !state) {
            try {
                workflowService.addRequestEntityRelationships(uuid, entities);
            } catch (InternalWorkflowException e) {
                // Debug exception which occurs at DB level since no workflows associated with event.
                if (log.isDebugEnabled()) {
                    log.debug("No workflow associated with the operation.", e);
                }
            }
        }
        return state;
    }

    @Override
    public String getEventId() {

        return UserStoreWFConstants.UPDATE_GROUP_USERS_EVENT;
    }

    @Override
    public Map<String, String> getParamDefinitions() {

        return PARAM_DEFINITION;
    }

    @Override
    public String getFriendlyName() {

        return FRIENDLY_NAME;
    }

    @Override
    public String getDescription() {

        return FRIENDLY_DESCRIPTION;
    }

    @Override
    public String getCategory() {

        return UserStoreWFConstants.CATEGORY_USERSTORE_OPERATIONS;
    }

    @Override
    public boolean retryNeedAtCallback() {

        return true;
    }

    @Override
    public void onWorkflowCompletion(String status, Map<String, Object> requestParams, Map<String, Object>
            responseAdditionalParams, int tenantId) throws WorkflowException {

        String groupName = (String) requestParams.get(GROUP_NAME);
        if (groupName == null) {
            throw new WorkflowException("Callback request for Update Group Users received without the mandatory " +
                    "parameter 'Group Name'.");
        }
        String userStoreDomain = (String) requestParams.get(USER_STORE_DOMAIN);
        if (StringUtils.isNotBlank(userStoreDomain)) {
            groupName = UserCoreUtil.addDomainToName(groupName, userStoreDomain);
        }

        List<String> deletedUserList = ((List<String>) requestParams.get(DELETED_USER_LIST));
        String[] deletedUsers;
        if (deletedUserList != null) {
            deletedUsers = new String[deletedUserList.size()];
            deletedUsers = deletedUserList.toArray(deletedUsers);
        } else {
            deletedUsers = new String[0];
        }

        List<String> newUserList = ((List<String>) requestParams.get(NEW_USER_LIST));
        String[] newUsers;
        if (newUserList != null) {
            newUsers = new String[newUserList.size()];
            newUsers = newUserList.toArray(newUsers);
        } else {
            newUsers = new String[0];
        }

        if (WorkflowRequestStatus.APPROVED.toString().equals(status) ||
                WorkflowRequestStatus.SKIPPED.toString().equals(status)) {
            try {
                RealmService realmService = IdentityWorkflowDataHolder.getInstance().getRealmService();
                UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
                userRealm.getUserStoreManager().updateUserListOfRole(groupName,
                        filterExistingUsers(deletedUsers, tenantId), filterExistingUsers(newUsers, tenantId));
            } catch (UserStoreException e) {
                // Sending e.getMessage() since it is required to give error message to end user.
                throw new WorkflowException(e.getMessage(), e);
            }
        } else {
            if (retryNeedAtCallback()) {
                // Unset threadlocal variable.
                unsetWorkFlowCompleted();
            }
            if (log.isDebugEnabled()) {
                log.debug("Updating group users is aborted for group '" + groupName +
                        "', Reason: Workflow response was " + status);
            }
        }
    }

    @Override
    public boolean isValidOperation(Entity[] entities) throws WorkflowException {

        WorkflowManagementService workflowService = IdentityWorkflowDataHolder.getInstance().getWorkflowService();
        RealmService realmService = IdentityWorkflowDataHolder.getInstance().getRealmService();
        UserRealm userRealm;
        AbstractUserStoreManager userStoreManager;
        try {
            userRealm = realmService.getTenantUserRealm(PrivilegedCarbonContext.getThreadLocalCarbonContext()
                    .getTenantId());
            userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager();
        } catch (UserStoreException e) {
            throw new WorkflowException("Error while retrieving user realm.", e);
        }
        Entity groupEntity = entities[0];
        for (Entity entity : entities) {
            try {
                if (UserStoreWFConstants.ENTITY_TYPE_USER.equals(entity.getEntityType())) {
                    // Check if the user has a pending deletion.
                    if (workflowService.entityHasPendingWorkflowsOfType(entity,
                            UserStoreWFConstants.DELETE_USER_EVENT)) {
                        throw new WorkflowException("There is a pending deletion workflow for the user: " +
                                entity.getEntityId());
                    // Check if the user has an existing pending workflow for the same group.
                    } else if (workflowService.areTwoEntitiesRelated(groupEntity, entity)) {
                        throw new WorkflowException("The user " + entity.getEntityId() +
                                " is already pending approval for the group.");
                    // Check if user does not exist in the system.
                    } else if (!userStoreManager.isExistingUser(entity.getEntityId())) {
                        throw new WorkflowException("The user " + entity.getEntityId() +
                                " is not found in the system for assigning to the group.");
                    }
                } else if (UserStoreWFConstants.ENTITY_TYPE_GROUP.equals(entity.getEntityType())) {
                    // Check if the group has a pending deletion.
                    if (workflowService.entityHasPendingWorkflowsOfType(entity,
                            UserStoreWFConstants.DELETE_GROUP_EVENT)) {
                        throw new WorkflowException("There is a pending workflow already defined for the group.");
                    // Check if the group does not exist in the system.
                    } else if (!userStoreManager.isExistingRole(entity.getEntityId())) {
                        throw new WorkflowException("The group " + entity.getEntityId() + " does not exist.");
                    }
                }
            } catch (InternalWorkflowException | org.wso2.carbon.user.core.UserStoreException e) {
                throw new WorkflowException(e.getMessage(), e);
            }
        }
        return true;
    }

    /**
     * Filters the list of users to only include those that exist in the user store.
     *
     * @param users    Array of usernames to filter.
     * @param tenantId Tenant ID.
     * @return Array of valid usernames that exist in the user store.
     * @throws WorkflowException If an error occurs while checking user existence.
     */
    private String[] filterExistingUsers(String[] users, int tenantId) throws WorkflowException {

        List<String> validUsers = new ArrayList<>();
        if (users == null || users.length == 0) {
            return new String[0];
        }
        RealmService realmService = IdentityWorkflowDataHolder.getInstance().getRealmService();
        try {
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) realmService
                    .getTenantUserRealm(tenantId).getUserStoreManager();
            for (String user : users) {
                if (StringUtils.isBlank(user)) {
                    continue;
                }
                if (userStoreManager.isExistingUser(user)) {
                    validUsers.add(user);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("User " + user + " does not exist in the system.");
                    }
                }
            }
        } catch (UserStoreException e) {
            throw new WorkflowException(e.getMessage(), e);
        }
        return validUsers.toArray(new String[0]);
    }
}
