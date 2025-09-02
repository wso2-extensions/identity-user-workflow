/*
 * Copyright (c) 2015-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.user.mgt.workflow;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.workflow.mgt.WorkflowManagementService;
import org.wso2.carbon.identity.workflow.mgt.exception.WorkflowException;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.mgt.workflow.internal.IdentityWorkflowDataHolder;

import java.util.HashMap;
import java.util.List;

import static org.wso2.carbon.user.mgt.workflow.util.UserStoreWFConstants.ADD_ROLE_EVENT;
import static org.wso2.carbon.user.mgt.workflow.util.UserStoreWFConstants.ADD_USER_EVENT;
import static org.wso2.carbon.user.mgt.workflow.util.UserStoreWFConstants.DELETE_ROLE_EVENT;
import static org.wso2.carbon.user.mgt.workflow.util.UserStoreWFConstants.DELETE_USER_EVENT;
/**
 * User Management Workflow Service class.
 */
public class UserManagementWorkflowService {

    private static final Log log = LogFactory.getLog(UserManagementWorkflowService.class);

    WorkflowManagementService workflowService = IdentityWorkflowDataHolder.getInstance().getWorkflowService();

    private static final String WORKFLOW_ADMIN_PERMISSION_CONFIG =
            "AdminServices.UserManagementWorkflowService.WorkflowServicePermission";
    private static final String DEFAULT_WORKFLOW_ADMIN_PERMISSION =
            "/permission/admin/manage/identity/workflow/association/view";
    private static final String USER_VIEW_PERMISSION = "/permission/admin/manage/identity/usermgt/view";
    private static final String ROLE_VIEW_PERMISSION = "/permission/admin/manage/identity/rolemgt/view";
    private static final HashMap<String, String> WORKFLOW_OPERATION_PERMISSIONS = new HashMap<String, String>() {{
        put(ADD_USER_EVENT, USER_VIEW_PERMISSION);
        put(ADD_ROLE_EVENT, ROLE_VIEW_PERMISSION);
        put(DELETE_USER_EVENT, USER_VIEW_PERMISSION);
        put(DELETE_ROLE_EVENT, ROLE_VIEW_PERMISSION);
    }};

    /**
     * Retrieve List of associated Entity-types of the workflow requests.
     *
     * @param wfOperationType Operation Type of the Work-flow.
     * @param wfStatus        Current Status of the Work-flow.
     * @param entityType      Entity Type of the Work-flow.
     * @param entityIdFilter  Entity ID filter to search
     * @return
     * @throws WorkflowException
     */

    public List<String> listAllEntityNames(String wfOperationType, String wfStatus, String entityType, String
            entityIdFilter) throws WorkflowException {

        int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        String loggedInName = CarbonContext.getThreadLocalCarbonContext().getUsername();

        if (!isUserAuthorized(tenantID, wfOperationType)) {
            throw new WorkflowException("Unauthorized access!! User " + loggedInName + " does not have permission to " +
                    "perform this operation.");
        }
        List<String> entityNames = workflowService.listEntityNames(wfOperationType, wfStatus, entityType, tenantID,
                entityIdFilter);
        return entityNames;

    }

    private boolean isUserAuthorized(int tenantId, String wfOperationType) throws WorkflowException {

        String loggedInName = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();

        AuthorizationManager authzManager = null;
        try {
            authzManager = IdentityWorkflowDataHolder.getInstance().getRealmService()
                    .getTenantUserRealm(tenantId).getAuthorizationManager();
        } catch (UserStoreException e) {
            throw new WorkflowException("Error occurred while retrieving AuthorizationManager for tenant "
                    + tenantDomain, e);
        }

        boolean isAuthorized = false;
        try {
            // Check for the generic workflow admin permission.
            String permission = (String) IdentityConfigParser.getInstance().getConfiguration()
                    .get(WORKFLOW_ADMIN_PERMISSION_CONFIG);
            if (StringUtils.isEmpty(permission)) {
                permission = DEFAULT_WORKFLOW_ADMIN_PERMISSION;
            }
            isAuthorized = authzManager.isUserAuthorized(loggedInName, permission,
                    CarbonConstants.UI_PERMISSION_ACTION);

            if (log.isDebugEnabled()) {
                log.debug("User does not have workflow general admin permission. Hence checking for specific " +
                        "operation permission.");
            }

            // Check for specific operation permission if not authorized yet.
            if (!isAuthorized && StringUtils.isNotEmpty(wfOperationType)) {
                if (WORKFLOW_OPERATION_PERMISSIONS.containsKey(wfOperationType)) {
                    isAuthorized = authzManager.isUserAuthorized(loggedInName,
                            WORKFLOW_OPERATION_PERMISSIONS.get(wfOperationType), CarbonConstants.UI_PERMISSION_ACTION);
                }
            }

        } catch (UserStoreException e) {
            throw new WorkflowException("Error occurred while checking access level for " +
                    "user " + loggedInName + " in tenant " + tenantDomain, e);
        }

        return isAuthorized;
    }
}
