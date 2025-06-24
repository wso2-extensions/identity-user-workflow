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

import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.listener.AbstractRoleManagementListener;
import org.wso2.carbon.identity.role.v2.mgt.core.listener.RoleManagementListener;
import org.wso2.carbon.identity.role.v2.mgt.core.model.Permission;
import org.wso2.carbon.identity.workflow.mgt.exception.WorkflowException;

import java.util.List;

public class RoleManagementActionListener extends AbstractRoleManagementListener{


    @Override
    public boolean isEnable() {
        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.readEventListenerProperty
                (RoleManagementListener.class.getName(), this.getClass().getName());
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
    public void preAddRole(String roleName, List<String> userList, List<String> groupList, List<Permission> permissions, String audience, String audienceId, String tenantDomain) throws IdentityRoleManagementException {

        if (!isEnable()) {
            return;
        }

        AddRoleWFRequestHandler addRoleWFRequestHandler = new AddRoleWFRequestHandler();
        try {
            boolean state = addRoleWFRequestHandler.startAddRoleFlow(roleName, userList, groupList, permissions, audience, audienceId, tenantDomain);
            // Throwing an exception if the workflow state is false, which indicates that the role creation request is
            // sent to the workflow engine for approval.
            if (!state) {
                throw new IdentityRoleManagementException(RoleConstants.Error.ROLE_WORKFLOW_CREATED.getCode(), "Role creation request is sent to the workflow engine for approval.");
            }
        } catch (WorkflowException e) {
            throw new IdentityRoleManagementException(e.getMessage(), e);
        }
    }




    @Override
    public void preGetRolesCount(String searchFilter, String tenantDomain) throws IdentityRoleManagementException {
        super.preGetRolesCount(searchFilter, tenantDomain);
    }

    @Override
    public void postGetRolesCount(int count, String searchFilter, String tenantDomain) throws IdentityRoleManagementException {
        super.postGetRolesCount(count, searchFilter, tenantDomain);
    }

    @Override
    public void preGetPermissionListOfRoles(List<String> roleIds, String tenantDomain) throws IdentityRoleManagementException {
        super.preGetPermissionListOfRoles(roleIds, tenantDomain);
    }

    @Override
    public void postGetPermissionListOfRoles(List<String> permissions, List<String> roleIds, String tenantDomain) throws IdentityRoleManagementException {
        super.postGetPermissionListOfRoles(permissions, roleIds, tenantDomain);
    }
}
