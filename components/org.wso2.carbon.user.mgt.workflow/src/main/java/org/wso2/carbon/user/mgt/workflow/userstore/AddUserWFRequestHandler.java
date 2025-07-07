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

package org.wso2.carbon.user.mgt.workflow.userstore;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
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

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.wso2.carbon.user.mgt.workflow.util.UserStoreWFUtils;

import static org.wso2.carbon.identity.workflow.mgt.util.WorkflowErrorConstants.ErrorMessages.ERROR_CODE_USER_WF_ALREADY_EXISTS;
import static org.wso2.carbon.identity.workflow.mgt.util.WorkflowErrorConstants.ErrorMessages.ERROR_CODE_USER_WF_ROLE_NOT_FOUND;
import static org.wso2.carbon.identity.workflow.mgt.util.WorkflowErrorConstants.ErrorMessages.ERROR_CODE_USER_WF_ROLE_PENDING_DELETION;
import static org.wso2.carbon.identity.workflow.mgt.util.WorkflowErrorConstants.ErrorMessages.ERROR_CODE_USER_WF_USER_ALREADY_EXISTS;
import static org.wso2.carbon.user.mgt.workflow.util.UserStoreWFUtils.getSelfRegistrationArbitraryProperties;
import static org.wso2.carbon.user.mgt.workflow.util.UserStoreWFUtils.setSelfRegistrationArbitraryProperties;

public class AddUserWFRequestHandler extends AbstractWorkflowRequestHandler {

    private static final String FRIENDLY_NAME = "Add User";
    private static final String FRIENDLY_DESCRIPTION = "Triggered when a new user is created.";

    private static final String USERNAME = "Username";
    private static final String USER_STORE_DOMAIN = "User Store Domain";
    private static final String CREDENTIAL = "Credential";
    private static final String ROLE_LIST = "Roles";
    private static final String CLAIM_LIST = "Claims";
    private static final String PROFILE = "Profile";
    private static final String ARBITRARY_ATTRIBUTE_PREFIX = "self_arbitrary_attr_";

    private static final Map<String, String> PARAM_DEFINITION;
    private static final Log log = LogFactory.getLog(AddUserWFRequestHandler.class);

    static {
        PARAM_DEFINITION = new LinkedHashMap<>();
        PARAM_DEFINITION.put(USERNAME, WorkflowDataType.STRING_TYPE);
        PARAM_DEFINITION.put(USER_STORE_DOMAIN, WorkflowDataType.STRING_TYPE);
        PARAM_DEFINITION.put(PROFILE, WorkflowDataType.STRING_TYPE);
        PARAM_DEFINITION.put(ROLE_LIST, WorkflowDataType.STRING_LIST_TYPE);
        PARAM_DEFINITION.put(CLAIM_LIST, WorkflowDataType.STRING_STRING_MAP_TYPE);
    }

    /**
     * Starts the workflow execution
     *
     * @param userStoreDomain
     * @param userName
     * @param credential
     * @param roleList
     * @param claims
     * @param profile
     * @return <code>true</code> if the workflow request is ready to be continued (i.e. has been approved from
     * workflow) <code>false</code> otherwise (i.e. request placed for approval)
     * @throws WorkflowException
     */
    public boolean startAddUserFlow(String userStoreDomain, String userName, Object credential, String[] roleList,
                                    Map<String, String> claims, String profile) throws WorkflowException {

        WorkflowManagementService workflowService = IdentityWorkflowDataHolder.getInstance().getWorkflowService();

        Map<String, Object> wfParams = new HashMap<>();
        Map<String, Object> nonWfParams = new HashMap<>();
        String encryptedCredentials = null;

        if (roleList == null) {
            roleList = new String[0];
        }
        if (claims == null) {
            claims = new HashMap<>();
        }
        int tenant = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        String fullyQualifiedName = UserCoreUtil.addDomainToName(userName, userStoreDomain);

        try {
            if (log.isDebugEnabled()) {
                log.debug("Encrypting the password of user " + " " + userName);
            }
            CryptoUtil cryptoUtil = CryptoUtil.getDefaultCryptoUtil();
            encryptedCredentials = cryptoUtil.
                    encryptAndBase64Encode((credential.toString()).getBytes(Charset.forName("UTF-8")));
        } catch (CryptoException e) {
            throw new WorkflowException("Error while encrypting the Credential for User Name" + " " + userName, e);
        }

        wfParams.put(USERNAME, userName);
        wfParams.put(USER_STORE_DOMAIN, userStoreDomain);
        wfParams.put(ROLE_LIST, Arrays.asList(roleList));
        wfParams.put(CLAIM_LIST, claims);
        wfParams.put(PROFILE, profile);
        nonWfParams.put(CREDENTIAL, encryptedCredentials);

        // Store self registration arbitrary attributes as non-workflow properties.
        Map<String, String> selfRegistrationArbitraryAttributes = getSelfRegistrationArbitraryProperties();
        for (Map.Entry<String, String> entry : selfRegistrationArbitraryAttributes.entrySet()) {
            nonWfParams.put(ARBITRARY_ATTRIBUTE_PREFIX + entry.getKey(), entry.getValue());
        }

        String uuid = UUID.randomUUID().toString();
        Entity[] entities = new Entity[roleList.length + 1];
        entities[0] = new Entity(fullyQualifiedName, UserStoreWFConstants.ENTITY_TYPE_USER, tenant);
        for (int i = 0; i < roleList.length; i++) {
            fullyQualifiedName = UserCoreUtil.addDomainToName(roleList[i], userStoreDomain);
            entities[i + 1] = new Entity(fullyQualifiedName, UserStoreWFConstants.ENTITY_TYPE_ROLE, tenant);
        }
        if (!Boolean.TRUE.equals(getWorkFlowCompleted()) && !isValidOperation(entities)) {
            throw new WorkflowException("Operation is not valid.");
        }
        boolean state = startWorkFlow(wfParams, nonWfParams, uuid).getExecutorResultState().state();

        //WF_REQUEST_ENTITY_RELATIONSHIP table has foreign key to WF_REQUEST, so need to run this after WF_REQUEST is
        // updated
        if (!Boolean.TRUE.equals(getWorkFlowCompleted()) && !state) {
            //ToDo: Add thread local to handle scenarios where workflow is not associated with the event.
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

        return UserStoreWFConstants.ADD_USER_EVENT;
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

        String userName;
        String decryptedCredentials;
        Object requestUsername = requestParams.get(USERNAME);
        Object credential = requestParams.get(CREDENTIAL);
        if (requestUsername == null || !(requestUsername instanceof String)) {
            throw new WorkflowException("Callback request for Add User received without the mandatory " +
                    "parameter 'username'");
        }
        String userStoreDomain = (String) requestParams.get(USER_STORE_DOMAIN);
        if (StringUtils.isNotBlank(userStoreDomain)) {
            userName = userStoreDomain + "/" + requestUsername;
        } else {
            userName = (String) requestUsername;
        }

        try {
            if (log.isDebugEnabled()) {
                log.debug("Decrypting the password of user " + userName);
            }
            CryptoUtil cryptoUtil = CryptoUtil.getDefaultCryptoUtil();
            byte[] decryptedBytes = cryptoUtil.base64DecodeAndDecrypt(credential.toString());
            decryptedCredentials = new String(decryptedBytes, "UTF-8");
            credential = decryptedCredentials;

        } catch (CryptoException | UnsupportedEncodingException e) {
            throw new WorkflowException("Error while decrypting the Credential for user " + userName, e);
        }

        List<String> roleList = ((List<String>) requestParams.get(ROLE_LIST));
        String[] roles;
        if (roleList != null) {
            roles = new String[roleList.size()];
            roles = roleList.toArray(roles);
        } else {
            roles = new String[0];
        }
        Map<String, String> claims = (Map<String, String>) requestParams.get(CLAIM_LIST);
        String profile = (String) requestParams.get(PROFILE);

        // Retrieve self registration arbitrary attributes and set to the thread local variable.
        Map<String, String> selfRegistrationArbitraryAttributes = new HashMap<>();
        for (Map.Entry<String, Object> params : requestParams.entrySet()) {
            if (params.getKey().startsWith(ARBITRARY_ATTRIBUTE_PREFIX)) {
                selfRegistrationArbitraryAttributes
                        .put(params.getKey().replace(ARBITRARY_ATTRIBUTE_PREFIX, ""), (String) params.getValue());
            }
        }

        if (!selfRegistrationArbitraryAttributes.isEmpty()) {
            setSelfRegistrationArbitraryProperties(selfRegistrationArbitraryAttributes);
        }

        if (WorkflowRequestStatus.APPROVED.toString().equals(status) ||
                WorkflowRequestStatus.SKIPPED.toString().equals(status)) {
            try {
                RealmService realmService = IdentityWorkflowDataHolder.getInstance().getRealmService();
                UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
                userRealm.getUserStoreManager().addUser(userName, credential, roles, claims, profile);
            } catch (UserStoreException e) {
                // Sending e.getMessage() since it is required to give error message to end user.
                throw new WorkflowException(e.getMessage(), e);
            }
        } else {
            if (retryNeedAtCallback()) {
                // Unset thread local variable.
                unsetWorkFlowCompleted();
            }
            if (log.isDebugEnabled()) {
                log.debug(
                        "Adding user is aborted for user '" + userName + "', Reason: Workflow response was " + status);
            }
        }
    }

    @Override
    public boolean isValidOperation(Entity[] entities) throws WorkflowException {

        WorkflowManagementService workflowService = IdentityWorkflowDataHolder.getInstance().getWorkflowService();
        if (!workflowService.isEventAssociated(UserStoreWFConstants.ADD_USER_EVENT)) {
            return true;
        }
        AbstractUserStoreManager userStoreManager = UserStoreWFUtils.getUserStoreManager();
        RoleManagementService roleManagementService = IdentityWorkflowDataHolder.getInstance()
                .getRoleManagementService();

        for (Entity entity : entities) {
            try {
                // User related validations.
                if (UserStoreWFConstants.ENTITY_TYPE_USER.equals(entity.getEntityType())) {
                    // Check if the user exists in the user store.
                    if (userStoreManager.isExistingUser(entity.getEntityId())) {
                        throw new WorkflowException(ERROR_CODE_USER_WF_USER_ALREADY_EXISTS.getMessage(),
                                ERROR_CODE_USER_WF_USER_ALREADY_EXISTS.getCode());
                    // Check if user already exists in pending add user workflow.
                    } else if (workflowService
                            .entityHasPendingWorkflowsOfType(entity, UserStoreWFConstants.ADD_USER_EVENT)) {
                        throw new WorkflowException(ERROR_CODE_USER_WF_ALREADY_EXISTS.getMessage(),
                                ERROR_CODE_USER_WF_ALREADY_EXISTS.getCode());
                    }
                }
                // Role related validations.
                else if (UserStoreWFConstants.ENTITY_TYPE_ROLE.equals(entity.getEntityType())) {
                    // Check if the role not exists in the user store.
                    if (!roleManagementService.isExistingRole(entity.getEntityId(),
                            CarbonContext.getThreadLocalCarbonContext().getTenantDomain())) {
                        throw new WorkflowException(String.format(ERROR_CODE_USER_WF_ROLE_NOT_FOUND.getMessage(),
                                entity.getEntityId()),
                                ERROR_CODE_USER_WF_ROLE_NOT_FOUND.getCode());
                    // Check if assigned role exists in the pending delete/update role  workflow.
                    } else if (workflowService.entityHasPendingWorkflowsOfType(entity,
                            UserStoreWFConstants.DELETE_ROLE_EVENT) ||
                            workflowService.entityHasPendingWorkflowsOfType(entity,
                                    UserStoreWFConstants.UPDATE_ROLE_NAME_EVENT)) {
                        throw new WorkflowException(String.format(ERROR_CODE_USER_WF_ROLE_PENDING_DELETION.getMessage(),
                                entity.getEntityId()),
                                ERROR_CODE_USER_WF_ROLE_PENDING_DELETION.getCode());
                    }
                }
            } catch (InternalWorkflowException | org.wso2.carbon.user.core.UserStoreException |
                     IdentityRoleManagementException e) {
                throw new WorkflowException(e.getMessage(), e);
            }
        }
        return true;
    }
}
