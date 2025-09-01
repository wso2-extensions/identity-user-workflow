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
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementClientException;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.listener.AbstractRoleManagementListener;
import org.wso2.carbon.identity.role.v2.mgt.core.listener.RoleManagementListener;
import org.wso2.carbon.identity.role.v2.mgt.core.model.Permission;
import org.wso2.carbon.identity.workflow.mgt.exception.WorkflowClientException;
import org.wso2.carbon.identity.workflow.mgt.exception.WorkflowException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.mgt.workflow.internal.IdentityWorkflowDataHolder;
import org.wso2.carbon.user.mgt.workflow.util.UserStoreWFConstants;

import java.util.ArrayList;
import java.util.List;

import static org.wso2.carbon.user.mgt.workflow.util.Util.isEventAssociatedWithWorkflow;

/**
 * Role management action listener.
 */
public class RoleManagementActionListener extends AbstractRoleManagementListener {

    @Override
    public boolean isEnable() {

        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.readEventListenerProperty(
                RoleManagementListener.class.getName(), this.getClass().getName());
        if (identityEventListenerConfig == null) {
            return false;
        }
        return Boolean.parseBoolean(identityEventListenerConfig.getEnable());
    }

    @Override
    public int getDefaultOrderId() {

        int orderId = getExecutionOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        return 10;
    }

    @Override
    public void preAddRole(String roleName, List<String> userList, List<String> groupList,
                           List<Permission> permissions, String audience, String audienceId, String tenantDomain)
            throws IdentityRoleManagementException {

        if (!isEnable() || !isEventAssociatedWithWorkflow(UserStoreWFConstants.ADD_ROLE_EVENT)
                || isRoleSharingOperation()) {
            return;
        }

        AddRoleV2WFRequestHandler addRoleWFRequestHandler = new AddRoleV2WFRequestHandler();
        try {
            boolean state = addRoleWFRequestHandler.startAddRoleFlow(roleName, userList, groupList, permissions,
                    audience, audienceId, tenantDomain);
            // Throwing an exception if the workflow state is false, which indicates that the role creation request is
            // sent to the workflow engine for approval.
            if (!state) {
                throw new IdentityRoleManagementException(RoleConstants.Error.ROLE_WORKFLOW_CREATED.getCode(), "Role " +
                        "creation request is sent to the workflow engine for approval.");
            }
        } catch (WorkflowClientException e) {
            throw new IdentityRoleManagementClientException(e.getErrorCode(), e.getMessage(), e);
        } catch (WorkflowException e) {
            throw new IdentityRoleManagementException(e.getErrorCode(), e.getMessage(), e);
        }
    }

    @Override
    public void preUpdateUserListOfRole(String roleId, List<String> newUserIDList, List<String> deletedUserIDList,
                                        String tenantDomain) throws IdentityRoleManagementException {

        if (!isEnable() || !isEventAssociatedWithWorkflow(UserStoreWFConstants.UPDATE_ROLE_V2_USERS_EVENT)) {
            return;
        }
        // If both new and deleted user lists are empty after filtering, return.
        if (containsOnlyAgentUsers(newUserIDList, deletedUserIDList)) {
            return;
        }
        UpdateRoleV2UsersWFRequestHandler addRoleWFRequestHandler = new UpdateRoleV2UsersWFRequestHandler();
        try {
            boolean state = addRoleWFRequestHandler.startUpdateRoleUsersFlow(roleId, newUserIDList,
                    deletedUserIDList, tenantDomain);
            // Throwing an exception if the workflow state is false, which indicates that the role update request is
            // sent to the workflow engine for approval.
            if (!state) {
                throw new IdentityRoleManagementException(RoleConstants.Error.ROLE_WORKFLOW_CREATED.getCode(),
                        "Role update request is sent to the workflow engine for approval.");
            }
        } catch (WorkflowException e) {
            throw new IdentityRoleManagementException(e.getErrorCode(), e.getMessage(), e);
        }
    }

    /**
     * Checks whether role creation is initiated as a result of role sharing.
     *
     * @return true if the flow is related to role sharing operation, false otherwise.
     */
    private boolean isRoleSharingOperation() {

        /* If the request initiated organization is different from the tenant domain, it indicates that the request
            is initiated from a different organization, which is a role sharing operation. */
        String requestInitiatedOrganization = IdentityTenantUtil.getTenantDomainFromContext();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        return !StringUtils.equals(requestInitiatedOrganization, tenantDomain);
    }

    /**
     * Checks whether the provided user ID lists contain only agent users.
     *
     * @param newUserIDList     List of new user IDs to be added to the role.
     * @param deletedUserIDList List of user IDs to be removed from the role.
     * @return true if both lists contain only agent users, false otherwise.
     * @throws IdentityRoleManagementException if an error occurs while checking user existence.
     */
    private boolean containsOnlyAgentUsers(List<String> newUserIDList, List<String> deletedUserIDList)
            throws IdentityRoleManagementException {

        return CollectionUtils.isEmpty(filterAgents(newUserIDList)) &&
                CollectionUtils.isEmpty(filterAgents(deletedUserIDList));
    }

    /**
     * Filters the list of user IDs to only include those that exist in the user store and are not from the agent
     * identity userstore.
     *
     * @param userIds List of user IDs to filter.
     * @return List of valid user IDs that exist in the user store and are not from the agent identity userstore.
     * @throws IdentityRoleManagementException if an error occurs while checking user existence.
     */
    private List<String> filterAgents(List<String> userIds) throws IdentityRoleManagementException {

        List<String> validUserIds = new ArrayList<>();
        if (CollectionUtils.isEmpty(userIds)) {
            return validUserIds;
        }
        AbstractUserStoreManager userStoreManager = getUserStoreManager();
        for (String userId : userIds) {
            try {
                if (StringUtils.isBlank(userId)) {
                    continue;
                }
                String username = userStoreManager.getUserNameFromUserID(userId);
                String domain = IdentityUtil.extractDomainFromName(username);
                if (userStoreManager.isExistingUserWithID(userId) &&
                        !IdentityUtil.getAgentIdentityUserstoreName().equals(domain)) {
                    validUserIds.add(userId);
                }
            } catch (org.wso2.carbon.user.core.UserStoreException e) {
                throw new IdentityRoleManagementException(e.getMessage(), e);
            }
        }
        return validUserIds;
    }

    /**
     * Get the user store manager.
     *
     * @return user store manager
     * @throws IdentityRoleManagementException if error while retrieving user realm
     */
    private AbstractUserStoreManager getUserStoreManager() throws IdentityRoleManagementException {

        RealmService realmService = IdentityWorkflowDataHolder.getInstance().getRealmService();
        UserRealm userRealm;
        AbstractUserStoreManager userStoreManager;
        try {
            userRealm = realmService.getTenantUserRealm(PrivilegedCarbonContext.getThreadLocalCarbonContext()
                    .getTenantId());
            userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager();
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new IdentityRoleManagementException("Error while retrieving user realm.", e);
        }
        return userStoreManager;
    }
}
