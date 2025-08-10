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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.model.Permission;
import org.wso2.carbon.identity.role.v2.mgt.core.util.RoleManagementUtils;
import org.wso2.carbon.identity.workflow.mgt.WorkflowManagementService;
import org.wso2.carbon.identity.workflow.mgt.bean.Entity;
import org.wso2.carbon.identity.workflow.mgt.bean.RoleEntity;
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
import static org.wso2.carbon.identity.workflow.mgt.util.WorkflowErrorConstants.ErrorMessages.ERROR_CODE_ROLE_WF_ROLE_ALREADY_EXISTS;
import static org.wso2.carbon.identity.workflow.mgt.util.WorkflowErrorConstants.ErrorMessages.ERROR_CODE_ROLE_WF_USER_NOT_FOUND;
import static org.wso2.carbon.identity.workflow.mgt.util.WorkflowErrorConstants.ErrorMessages.ERROR_CODE_ROLE_WF_USER_PENDING_DELETION;

/**
 * Add roleV2 workflow request handler.
 */
public class AddRoleV2WFRequestHandler extends AbstractWorkflowRequestHandler {

    private static final String FRIENDLY_NAME = "Add Role";
    private static final String FRIENDLY_DESCRIPTION = "Triggered when a user create a new role.";
    private static final String ROLE_NAME = "Role Name";
    private static final String PERMISSIONS = "Permissions";
    private static final String USER_LIST = "Users";
    private static final String GROUPS_LIST = "Groups";
    private static final String AUDIENCE = "Audience";
    private static final String AUDIENCE_ID = "Audience ID";
    private static final String TENANT_DOMAIN = "Tenant Domain";

    private static final Map<String, String> PARAM_DEFINITION;
    private static final Log log = LogFactory.getLog(AddRoleV2WFRequestHandler.class);

    static {
        PARAM_DEFINITION = new LinkedHashMap<>();
        PARAM_DEFINITION.put(ROLE_NAME, WorkflowDataType.STRING_TYPE);
        PARAM_DEFINITION.put(USER_LIST, WorkflowDataType.STRING_LIST_TYPE);
        PARAM_DEFINITION.put(GROUPS_LIST, WorkflowDataType.STRING_LIST_TYPE);
        PARAM_DEFINITION.put(PERMISSIONS, WorkflowDataType.STRING_LIST_TYPE);
        PARAM_DEFINITION.put(AUDIENCE, WorkflowDataType.STRING_TYPE);
        PARAM_DEFINITION.put(AUDIENCE_ID, WorkflowDataType.STRING_TYPE);
        PARAM_DEFINITION.put(TENANT_DOMAIN, WorkflowDataType.STRING_TYPE);
    }

    public boolean startAddRoleFlow(String roleName, List<String> userList, List<String> groupList,
                                    List<Permission> permissions, String audience, String audienceId,
                                    String tenantDomain)
            throws WorkflowException, IdentityRoleManagementException {

        WorkflowManagementService workflowService = IdentityWorkflowDataHolder.getInstance().getWorkflowService();
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

        Map<String, Object> wfParams = new HashMap<>();
        Map<String, Object> nonWfParams = new HashMap<>();
        wfParams.put(ROLE_NAME, roleName);
        wfParams.put(USER_LIST, userList);
        List<String> permissionNames = new ArrayList<>();
        if (!permissions.isEmpty()) {
            permissionNames = getPermissionNames(permissions);
        }
        wfParams.put(PERMISSIONS, permissionNames);
        wfParams.put(GROUPS_LIST, groupList);
        if (StringUtils.isEmpty(audience)) {
            audience = RoleConstants.ORGANIZATION;
        }
        wfParams.put(AUDIENCE, audience);
        if (StringUtils.isEmpty(audienceId)) {
            audienceId = RoleManagementUtils.getOrganizationIdByTenantDomain(tenantDomain);
        }
        wfParams.put(AUDIENCE_ID, audienceId);
        wfParams.put(TENANT_DOMAIN, tenantDomain);
        String uuid = UUID.randomUUID().toString();
        RoleEntity[] entities = new RoleEntity[userList.size() + 1];
        entities[0] = new RoleEntity(roleName, UserStoreWFConstants.ENTITY_TYPE_ROLE, tenantId, audience,
                audienceId);
        for (int i = 0; i < userList.size(); i++) {
            entities[i + 1] = new RoleEntity(userList.get(i), UserStoreWFConstants.ENTITY_TYPE_USER, tenantId,
                    audience, audienceId);
        }
        if (!Boolean.TRUE.equals(getWorkFlowCompleted()) && !isValidOperation(entities)) {
            throw new WorkflowException("Operation is not valid");
        }

        boolean state = startWorkFlow(wfParams, nonWfParams, uuid).getExecutorResultState().state();

        // WF_REQUEST_ENTITY_RELATIONSHIP table has foreign key to WF_REQUEST, so need to run this after WF_REQUEST is
        // updated.
        if (!Boolean.TRUE.equals(getWorkFlowCompleted()) && !state) {
            try {
                workflowService.addRequestEntityRelationships(uuid, entities);
            } catch (InternalWorkflowException e) {
                //debug exception which occurs at DB level since no workflows associated with event
                if (log.isDebugEnabled()) {
                    log.debug("No workflow associated with the operation.", e);
                }
            }
        }
        return state;
    }

    @Override
    public String getEventId() {
        return UserStoreWFConstants.ADD_ROLE_EVENT;
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

        String roleName = (String) requestParams.get(ROLE_NAME);
        if (roleName == null) {
            throw new WorkflowException("Callback request for Add role received without the mandatory " +
                    "parameter 'roleName'");
        }

        String audience = (String) requestParams.get(AUDIENCE);
        String audienceId = (String) requestParams.get(AUDIENCE_ID);
        String tenantDomain = (String) requestParams.get(TENANT_DOMAIN);
        List<String> userList = (List<String>) requestParams.get(USER_LIST);
        List<String> groupList = (List<String>) requestParams.get(GROUPS_LIST);
        List<String> permissionNames = (List<String>) requestParams.get(PERMISSIONS);
        List<Permission> permissions = new ArrayList<>();
        if (permissionNames != null) {
            permissions = getPermissionsFromNames(permissionNames);
        }

        if (WorkflowRequestStatus.APPROVED.toString().equals(status) ||
                WorkflowRequestStatus.SKIPPED.toString().equals(status)) {
            try {
                IdentityWorkflowDataHolder.getInstance().getRoleManagementService().addRole(roleName, userList,
                        groupList, permissions, audience, audienceId, tenantDomain);
            } catch (IdentityRoleManagementException e) {
                throw new WorkflowException("Error while creating the role", e);
            }
        } else {
            if (retryNeedAtCallback()) {
                // unset thread local variable.
                unsetWorkFlowCompleted();
            }
            if (log.isDebugEnabled()) {
                log.debug(
                        "Adding role is aborted for role '" + roleName + "', Reason: Workflow response was " + status);
            }
        }
    }

    @Override
    public boolean isValidOperation(Entity[] entities) throws WorkflowException {

        WorkflowManagementService workflowService = IdentityWorkflowDataHolder.getInstance().getWorkflowService();
        AbstractUserStoreManager userStoreManager = UserStoreWFUtils.getUserStoreManager();
        RoleManagementService roleManagementService = IdentityWorkflowDataHolder.getInstance()
                .getRoleManagementService();

        for (Entity entity : entities) {
            RoleEntity roleEntity = (RoleEntity) entity;
            try {
                // Role related validations.
                if (UserStoreWFConstants.ENTITY_TYPE_ROLE.equals(roleEntity.getEntityType())) {
                    // Check if the role name exists in the role add workflow.
                    if (workflowService
                            .entityHasPendingWorkflowsOfType(roleEntity, UserStoreWFConstants.ADD_ROLE_EVENT)) {
                        throw new WorkflowException(ERROR_CODE_ROLE_WF_PENDING_ALREADY_EXISTS.getMessage(),
                                ERROR_CODE_ROLE_WF_PENDING_ALREADY_EXISTS.getCode());
                        // Check if the role name already exists in the system.
                    } else if (roleManagementService.isExistingRoleName(roleEntity.getEntityId(),
                            roleEntity.getAudience(), roleEntity.getAudienceId(),
                            IdentityTenantUtil.getTenantDomain(roleEntity.getTenantId()))) {
                        throw new WorkflowException(ERROR_CODE_ROLE_WF_ROLE_ALREADY_EXISTS.getMessage(),
                                ERROR_CODE_ROLE_WF_ROLE_ALREADY_EXISTS.getCode());
                    }
                    // User related validations.
                } else if (UserStoreWFConstants.ENTITY_TYPE_USER.equals(roleEntity.getEntityType())) {
                    // Check if the user exists in the user store.
                    if (!userStoreManager.isExistingUserWithID(roleEntity.getEntityId())) {
                        throw new WorkflowException(String.format(ERROR_CODE_ROLE_WF_USER_NOT_FOUND.getMessage(),
                                entity.getEntityId()),
                                ERROR_CODE_ROLE_WF_USER_NOT_FOUND.getCode());
                        // Check if the user already pending in the user delete approval workflow.
                    } else if (workflowService
                            .entityHasPendingWorkflowsOfType(roleEntity, UserStoreWFConstants.DELETE_USER_EVENT)) {
                        throw new WorkflowException(String.format(ERROR_CODE_ROLE_WF_USER_PENDING_DELETION.getMessage(),
                                entity.getEntityId()),
                                ERROR_CODE_ROLE_WF_USER_PENDING_DELETION.getCode());
                    }
                }
            } catch (InternalWorkflowException | org.wso2.carbon.user.core.UserStoreException |
                     IdentityRoleManagementException e) {
                throw new WorkflowException(e.getMessage(), e);
            }
        }
        return true;
    }

    private List<String> getPermissionNames(List<Permission> permissions) {

        List<String> permissionNames = new ArrayList<>();
        for (Permission permission : permissions) {
            permissionNames.add(permission.getName());
        }
        return permissionNames;
    }

    private List<Permission> getPermissionsFromNames(List<String> permissionNames) {

        List<Permission> permissions = new ArrayList<>();
        for (String permissionName : permissionNames) {
            Permission permission = new Permission(permissionName);
            permissions.add(permission);
        }
        return permissions;
    }
}
