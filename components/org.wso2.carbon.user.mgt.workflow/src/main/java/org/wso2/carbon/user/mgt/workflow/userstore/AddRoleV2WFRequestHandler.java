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
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.role.v2.mgt.core.dao.RoleDAO;
import org.wso2.carbon.identity.role.v2.mgt.core.dao.RoleMgtDAOFactory;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementClientException;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.util.RoleManagementUtils;
import org.wso2.carbon.identity.workflow.mgt.WorkflowManagementService;
import org.wso2.carbon.identity.workflow.mgt.bean.Entity;
import org.wso2.carbon.identity.workflow.mgt.exception.InternalWorkflowException;
import org.wso2.carbon.identity.workflow.mgt.exception.WorkflowException;
import org.wso2.carbon.identity.workflow.mgt.extension.AbstractWorkflowRequestHandler;
import org.wso2.carbon.identity.workflow.mgt.util.WorkflowDataType;
import org.wso2.carbon.identity.workflow.mgt.util.WorkflowRequestStatus;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.identity.role.v2.mgt.core.model.Permission;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.mgt.workflow.internal.IdentityWorkflowDataHolder;
import org.wso2.carbon.user.mgt.workflow.util.UserStoreWFConstants;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.ArrayList;

import static org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants.APPLICATION;
import static org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants.Error.INVALID_AUDIENCE;
import static org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants.ORGANIZATION;

public class AddRoleV2WFRequestHandler extends AbstractWorkflowRequestHandler {

    private static final String FRIENDLY_NAME = "Add Role";
    private static final String FRIENDLY_DESCRIPTION = "Triggered when a user create a new role.";
    private static final String ROLE_NAME = "Role Name";
    private static final String USER_STORE_DOMAIN = "User Store Domain";
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
        PARAM_DEFINITION.put(USER_STORE_DOMAIN, WorkflowDataType.STRING_TYPE);
        PARAM_DEFINITION.put(USER_LIST, WorkflowDataType.STRING_LIST_TYPE);
        PARAM_DEFINITION.put(PERMISSIONS, WorkflowDataType.STRING_LIST_TYPE);
    }

    public boolean startAddRoleFlow(String roleName, List<String> userList, List<String> groupList,
                                    List<Permission> permissions, String audience, String audienceId,
                                    String tenantDomain)
            throws WorkflowException {

        WorkflowManagementService workflowService = IdentityWorkflowDataHolder.getInstance().getWorkflowService();
        int tenant = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        Map<String, Object> wfParams = new HashMap<>();
        Map<String, Object> nonWfParams = new HashMap<>();
        wfParams.put(ROLE_NAME, roleName);
        wfParams.put(USER_LIST, userList);
        List<String> permissionNames = null;
        if (!permissions.isEmpty()) {
            permissionNames = getPermissionNames(permissions);
        }
        wfParams.put(PERMISSIONS, permissionNames);
        wfParams.put(GROUPS_LIST, groupList);
        wfParams.put(AUDIENCE, audience);
        wfParams.put(AUDIENCE_ID, audienceId);
        wfParams.put(TENANT_DOMAIN, tenantDomain);
        String uuid = UUID.randomUUID().toString();
        Entity[] entities = new Entity[userList.size() + 1];
        entities[0] = new Entity(roleName, UserStoreWFConstants.ENTITY_TYPE_ROLE, tenant);
        for (int i = 0; i < userList.size(); i++) {
            entities[i + 1] = new Entity(userList.get(i), UserStoreWFConstants.ENTITY_TYPE_USER, tenant);
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
        List<Permission> permissions = null;
        if (permissionNames != null) {
            permissions = getPermissionsFromNames(permissionNames);
        }

        // Validate the audience.
        try {
            if (StringUtils.isNotEmpty(audience)) {
                if (!(ORGANIZATION.equalsIgnoreCase(audience) || APPLICATION.equalsIgnoreCase(audience))) {
                    throw new IdentityRoleManagementClientException(INVALID_AUDIENCE.getCode(),
                            "Invalid role audience");
                }
                if (ORGANIZATION.equalsIgnoreCase(audience)) {
                    RoleManagementUtils.validateOrganizationRoleAudience(audienceId, tenantDomain);
                    audience = ORGANIZATION;
                }
                if (APPLICATION.equalsIgnoreCase(audience)) {
                    // audience validation done using listener.
                    audience = APPLICATION;
                }
            } else {
                audience = ORGANIZATION;
                audienceId = RoleManagementUtils.getOrganizationIdByTenantDomain(tenantDomain);
            }
        } catch (IdentityRoleManagementException e) {
            throw new WorkflowException("Error while validating role audience: " + e.getMessage(), e);
        }

        if (WorkflowRequestStatus.APPROVED.toString().equals(status) ||
                WorkflowRequestStatus.SKIPPED.toString().equals(status)) {
            try {
                RoleDAO roleDAO = RoleMgtDAOFactory.getInstance().getRoleDAO();
                RoleManagementUtils.validatePermissions(permissions, audience, tenantDomain);
                roleDAO.addRole(roleName, userList, groupList, permissions, audience,
                        audienceId, tenantDomain);
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

        RealmService realmService = IdentityWorkflowDataHolder.getInstance().getRealmService();
        UserRealm userRealm;
        AbstractUserStoreManager userStoreManager;
        RoleDAO roleDAO;
        try {
            userRealm = realmService.getTenantUserRealm(PrivilegedCarbonContext.getThreadLocalCarbonContext()
                    .getTenantId());
            userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager();
            roleDAO = RoleMgtDAOFactory.getInstance().getRoleDAO();
        } catch (UserStoreException e) {
            throw new WorkflowException("Error while retrieving user realm.", e);
        }
        for (Entity entity : entities) {
            try {
                if (UserStoreWFConstants.ENTITY_TYPE_ROLE.equals(entity.getEntityType()) && (workflowService
                        .entityHasPendingWorkflowsOfType(entity, UserStoreWFConstants.ADD_ROLE_EVENT) ||
                        workflowService.entityHasPendingWorkflowsOfType(entity, UserStoreWFConstants
                                .UPDATE_ROLE_NAME_EVENT) ||
                        roleDAO.isExistingRoleID(entity.getEntityId(),
                                CarbonContext.getThreadLocalCarbonContext().getTenantDomain()))) {
                    throw new WorkflowException("Role name already exists in the system. Please pick another role " +
                            "name.");
                } else if (workflowService.isEventAssociated(UserStoreWFConstants.ADD_USER_EVENT) &&
                        UserStoreWFConstants.ENTITY_TYPE_USER.equals(entity.getEntityType()) && workflowService
                        .entityHasPendingWorkflowsOfType(entity, UserStoreWFConstants.DELETE_USER_EVENT)) {
                    throw new WorkflowException("One or more assigned users are pending in delete workflow.");
                } else if (UserStoreWFConstants.ENTITY_TYPE_USER.equals(entity.getEntityType()) &&
                        !userStoreManager.isExistingUserWithID(entity.getEntityId())) {
                    throw new WorkflowException("User " + entity.getEntityId() + " does not exist.");
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
