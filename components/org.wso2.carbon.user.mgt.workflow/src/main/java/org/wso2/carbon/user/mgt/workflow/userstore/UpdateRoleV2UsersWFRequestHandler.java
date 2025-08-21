/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.workflow.mgt.WorkflowManagementService;
import org.wso2.carbon.identity.workflow.mgt.bean.Entity;
import org.wso2.carbon.identity.workflow.mgt.exception.InternalWorkflowException;
import org.wso2.carbon.identity.workflow.mgt.exception.WorkflowException;
import org.wso2.carbon.identity.workflow.mgt.extension.AbstractWorkflowRequestHandler;
import org.wso2.carbon.identity.workflow.mgt.util.WorkflowDataType;
import org.wso2.carbon.identity.workflow.mgt.util.WorkflowRequestStatus;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.mgt.workflow.internal.IdentityWorkflowDataHolder;
import org.wso2.carbon.user.mgt.workflow.util.UserStoreWFConstants;
import org.wso2.carbon.user.mgt.workflow.util.UserStoreWFUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.wso2.carbon.identity.workflow.mgt.util.WorkflowErrorConstants.ErrorMessages.ERROR_CODE_ROLE_WF_PENDING_ALREADY_EXISTS;
import static org.wso2.carbon.identity.workflow.mgt.util.WorkflowErrorConstants.ErrorMessages.ERROR_CODE_ROLE_WF_ROLE_NOT_FOUND;
import static org.wso2.carbon.identity.workflow.mgt.util.WorkflowErrorConstants.ErrorMessages.ERROR_CODE_ROLE_WF_USER_NOT_FOUND;
import static org.wso2.carbon.identity.workflow.mgt.util.WorkflowErrorConstants.ErrorMessages.ERROR_CODE_ROLE_WF_USER_PENDING_APPROVAL_FOR_ROLE;
import static org.wso2.carbon.identity.workflow.mgt.util.WorkflowErrorConstants.ErrorMessages.ERROR_CODE_ROLE_WF_USER_PENDING_DELETION;

/**
 * Update Users of RoleV2 workflow request handler.
 */
public class UpdateRoleV2UsersWFRequestHandler extends AbstractWorkflowRequestHandler {

    private static final String FRIENDLY_NAME = "Update Users Of Role";
    private static final String FRIENDLY_DESCRIPTION = "Triggered when users are added or removed from a role.";

    private static final String ROLE_ID = "Role ID";
    private static final String NEW_USER_ID_LIST = "Users to be Added";
    private static final String DELETED_USER_ID_LIST = "Users to be Deleted";
    private static final String TENANT_DOMAIN = "Tenant Domain";
    
    private static final Map<String, String> PARAM_DEFINITION;
    private static final Log log = LogFactory.getLog(UpdateRoleV2UsersWFRequestHandler.class);

    static {
        PARAM_DEFINITION = new LinkedHashMap<>();
        PARAM_DEFINITION.put(ROLE_ID, WorkflowDataType.STRING_TYPE);
        PARAM_DEFINITION.put(NEW_USER_ID_LIST, WorkflowDataType.STRING_LIST_TYPE);
        PARAM_DEFINITION.put(DELETED_USER_ID_LIST, WorkflowDataType.STRING_LIST_TYPE);
        PARAM_DEFINITION.put(TENANT_DOMAIN, WorkflowDataType.STRING_TYPE);
    }

    public boolean startUpdateRoleUsersFlow(String roleId, List<String> newUserIDList, List<String> deletedUserIDList,
                                            String tenantDomain) throws WorkflowException {

        WorkflowManagementService workflowService = IdentityWorkflowDataHolder.getInstance().getWorkflowService();

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Map<String, Object> wfParams = new HashMap<>();
        Map<String, Object> nonWfParams = new HashMap<>();

        wfParams.put(ROLE_ID, roleId);
        wfParams.put(NEW_USER_ID_LIST, newUserIDList);
        wfParams.put(DELETED_USER_ID_LIST, deletedUserIDList);
        wfParams.put(TENANT_DOMAIN, tenantDomain);

        String uuid = UUID.randomUUID().toString();
        List<Entity> entityList = new ArrayList<>();
        entityList.add(new Entity(roleId, UserStoreWFConstants.ENTITY_TYPE_ROLE, tenantId));
        for (String newUserId : newUserIDList) {
            entityList.add(new Entity(newUserId, UserStoreWFConstants.ENTITY_TYPE_USER, tenantId));
        }

        for (String deletedUserId : deletedUserIDList) {
            entityList.add(new Entity(deletedUserId, UserStoreWFConstants.ENTITY_TYPE_USER, tenantId));
        }
        Entity[] entities = entityList.toArray(new Entity[0]);
        if (!Boolean.TRUE.equals(getWorkFlowCompleted()) && !isValidOperation(entities)) {
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
        return UserStoreWFConstants.UPDATE_ROLE_V2_USERS_EVENT;
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

        String roleId = (String) requestParams.get(ROLE_ID);
        if (roleId == null) {
            throw new WorkflowException("Callback request for update assigned users of role is received without the " +
                    "mandatory parameter 'role id.'");
        }

        List<String> newUsers = ((List<String>) requestParams.get(NEW_USER_ID_LIST));
        List<String> deletedUsers = ((List<String>) requestParams.get(DELETED_USER_ID_LIST));
        String tenantDomain = (String) requestParams.get(TENANT_DOMAIN);

        if (WorkflowRequestStatus.APPROVED.toString().equals(status) ||
                WorkflowRequestStatus.SKIPPED.toString().equals(status)) {

            RoleManagementService roleManagementService = IdentityWorkflowDataHolder.getInstance()
                    .getRoleManagementService();
            try {
                roleManagementService.updateUserListOfRole(roleId, filterExistingUserIds(newUsers),
                        filterExistingUserIds(deletedUsers), tenantDomain);
            } catch (IdentityRoleManagementException e) {
                throw new WorkflowException(e.getMessage(), e);
            }
        } else {
            if (retryNeedAtCallback()) {
                // Unset thread local variable.
                unsetWorkFlowCompleted();
            }
            if (log.isDebugEnabled()) {
                log.debug(
                        "Updating role users is aborted for role '" + roleId + "', Reason: Workflow response was " +
                                status);
            }
        }
    }

    @Override
    public boolean isValidOperation(Entity[] entities) throws WorkflowException {

        WorkflowManagementService workflowService = IdentityWorkflowDataHolder.getInstance().getWorkflowService();
        AbstractUserStoreManager userStoreManager = UserStoreWFUtils.getUserStoreManager();
        RoleManagementService roleManagementService = IdentityWorkflowDataHolder.getInstance()
                .getRoleManagementService();
        Entity roleEntity = entities[0];
        for (Entity entity : entities) {
            try {
                // User related validations.
                if (UserStoreWFConstants.ENTITY_TYPE_USER.equals(entity.getEntityType())) {
                    // Check if the user has pending deletion.
                    if (workflowService.entityHasPendingWorkflowsOfType(entity,
                            UserStoreWFConstants.DELETE_USER_EVENT)) {
                        throw new WorkflowException(String.format(ERROR_CODE_ROLE_WF_USER_PENDING_DELETION.getMessage(),
                                entity.getEntityId(),
                                ERROR_CODE_ROLE_WF_USER_PENDING_DELETION.getCode()));
                    // Check if user has existing role assignment with the given role.
                    } else if (workflowService.areTwoEntitiesRelated(roleEntity, entity)) {
                        throw new WorkflowException(
                                String.format(ERROR_CODE_ROLE_WF_USER_PENDING_APPROVAL_FOR_ROLE.getMessage(),
                                        entity.getEntityId()),
                                ERROR_CODE_ROLE_WF_USER_PENDING_APPROVAL_FOR_ROLE.getCode());
                    // Check if user not exists in the system.
                    } else if (!userStoreManager.isExistingUserWithID(entity.getEntityId())) {
                        throw new WorkflowException(String.format(ERROR_CODE_ROLE_WF_USER_NOT_FOUND.getMessage(),
                                entity.getEntityId()),
                                ERROR_CODE_ROLE_WF_USER_NOT_FOUND.getCode());
                    }
                } else if (UserStoreWFConstants.ENTITY_TYPE_ROLE.equals(entity.getEntityType())) {
                    // Check if the role has a pending deletion or update operation.
                    if (workflowService
                            .entityHasPendingWorkflowsOfType(entity, UserStoreWFConstants.DELETE_ROLE_EVENT) ||
                            workflowService.entityHasPendingWorkflowsOfType(entity, UserStoreWFConstants
                                    .UPDATE_ROLE_NAME_EVENT)) {
                        throw new WorkflowException(ERROR_CODE_ROLE_WF_PENDING_ALREADY_EXISTS.getMessage(),
                                ERROR_CODE_ROLE_WF_PENDING_ALREADY_EXISTS.getCode());
                    // Check if the role not exists in the system.
                    } else if (!roleManagementService.isExistingRole(entity.getEntityId(),
                            IdentityTenantUtil.getTenantDomain(entity.getTenantId()))) {
                        throw new WorkflowException(ERROR_CODE_ROLE_WF_ROLE_NOT_FOUND.getMessage(),
                                ERROR_CODE_ROLE_WF_ROLE_NOT_FOUND.getCode());
                    }
                }
            } catch (InternalWorkflowException | org.wso2.carbon.user.core.UserStoreException |
                     IdentityRoleManagementException e) {
                throw new WorkflowException(e.getMessage(), e);
            }
        }
        return true;
    }

    /**
     * Filters the list of user IDs to only include those that exist in the user store.
     *
     * @param userIds List of user IDs to filter.
     * @return List of valid user IDs that exist in the user store.
     * @throws WorkflowException if an error occurs while checking user existence.
     */
    private List<String> filterExistingUserIds(List<String> userIds) throws WorkflowException {

        List<String> validUserIds = new ArrayList<>();
        if (CollectionUtils.isEmpty(userIds)) {
            return validUserIds;
        }
        AbstractUserStoreManager userStoreManager = UserStoreWFUtils.getUserStoreManager();
        for (String userId : userIds) {
            try {
                if (StringUtils.isBlank(userId)) {
                    continue;
                }
                if (userStoreManager.isExistingUserWithID(userId)) {
                    validUserIds.add(userId);
                } else {
                    log.debug("User with ID: " + userId + " does not exist.");
                }
            } catch (org.wso2.carbon.user.core.UserStoreException e) {
                throw new WorkflowException(e.getMessage(), e);
            }
        }
        return validUserIds;
    }
}
