/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.password.policy.constants.PasswordPolicyConstants;
import org.wso2.carbon.user.api.Permission;
import org.wso2.carbon.user.api.TenantManager;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.user.mgt.workflow.internal.IdentityWorkflowDataHolder;
import org.wso2.carbon.user.mgt.workflow.util.ValidationResult;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.user.core.constants.UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_PASSWORD;
import static org.wso2.carbon.user.core.constants.UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_USER_NAME;
import static org.wso2.carbon.user.mgt.workflow.util.UserStoreWFUtils.isPasswordValid;
import static org.wso2.carbon.user.mgt.workflow.util.UserStoreWFUtils.isUsernameValid;
import static org.wso2.carbon.user.mgt.workflow.util.UserStoreWFUtils.triggerAddUserFailureListeners;

public class UserStoreActionListener extends AbstractIdentityUserOperationEventListener {

    public static final String DO_PRE_AUTHENTICATE_IDENTITY_PROPERTY = "doPreAuthenticate";
    public static final String DO_POST_AUTHENTICATE_IDENTITY_PROPERTY = "doPostAuthenticate";
    public static final String DO_POST_ADD_USER_IDENTITY_PROPERTY = "doPostAddUser";
    public static final String DO_PRE_SET_USER_CLAIM_VALUES_IDENTITY_PROPERT = "doPreSetUserClaimValues";
    public static final String DO_POST_UPDATE_CREDENTIAL_IDENTITY_PROPERTY = "doPostUpdateCredential";
    private static final Log log = LogFactory.getLog(UserStoreActionListener.class);

    @Override
    public int getExecutionOrderId() {
        int orderId = getOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        return 10;
    }


    @Override
    public boolean doPreAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims,
                                String profile, UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable() || isCalledViaIdentityMgtListners()) {
            return true;
        }

        ValidationResult usernameValidationResult = isUsernameValid(userName, userStoreManager.getRealmConfiguration());
        if (!usernameValidationResult.isValid()  && !UserCoreUtil.getSkipUsernamePatternValidationThreadLocal()) {
            String errorCode = ERROR_CODE_INVALID_USER_NAME.getCode();
            String errorMessage = String
                    .format(ERROR_CODE_INVALID_USER_NAME.getMessage(), UserCoreUtil.removeDomainFromName(userName),
                            usernameValidationResult.getRegExUsed());

            triggerAddUserFailureListeners(errorCode, errorMessage, userName, credential, roleList, claims, profile,
                    userStoreManager);
            throw new UserStoreException(errorCode + " - " + errorMessage);
        }

        ValidationResult passwordValidationResult = isPasswordValid(credential,
                userStoreManager.getRealmConfiguration());
        // Check if the skipPasswordPatternValidationThreadLocal is set to false and password is invalid.
        if (!UserCoreUtil.getSkipPasswordPatternValidationThreadLocal() && !passwordValidationResult.isValid()) {
            String errorCode = ERROR_CODE_INVALID_PASSWORD.getCode();
            String errorMessage = String
                    .format(ERROR_CODE_INVALID_PASSWORD.getMessage(), passwordValidationResult.getRegExUsed());
            triggerAddUserFailureListeners(errorCode, errorMessage, userName, credential, roleList, claims,
                    profile, userStoreManager);
            throw new UserStoreException(errorCode + " - " + errorMessage);
        }

        doPasswordPolicyValidation(userName, credential, userStoreManager);

        return true;
    }

    @Override
    public boolean doPreUpdateCredential(String userName, Object newCredential, Object oldCredential,
                                         UserStoreManager userStoreManager) throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPreUpdateCredentialByAdmin(String s, Object o, UserStoreManager userStoreManager) throws
            UserStoreException {
        return true;
    }

    @Override
    public boolean doPreDeleteUser(String userName, UserStoreManager userStoreManager) throws UserStoreException {

        return true;
    }

    @Override
    public boolean doPreSetUserClaimValue(String userName, String claimURI, String claimValue, String profileName,
                                          UserStoreManager userStoreManager) throws UserStoreException {

        return true;
    }

    @Override
    public boolean doPreSetUserClaimValues(String userName, Map<String, String> claims, String profileName,
                                           UserStoreManager userStoreManager) throws UserStoreException {

        return true;
    }

    @Override
    public boolean doPreDeleteUserClaimValues(String userName, String[] claims, String profileName, UserStoreManager
            userStoreManager) throws UserStoreException {

        return true;
    }

    @Override
    public boolean doPreDeleteUserClaimValue(String userName, String claimURI, String profileName,
                                             UserStoreManager userStoreManager) throws UserStoreException {

        return true;
    }

    @Override
    public boolean doPreAddRole(String roleName, String[] userList, Permission[] permissions, UserStoreManager
            userStoreManager) throws UserStoreException {

        return true;
    }

    @Override
    public boolean doPreAddInternalRoleWithID(String roleName, String[] userIDList, Permission[] permissions,
                                              UserStoreManager userStoreManager) throws UserStoreException {

        String[] userNames = getUserNamesFromUserIDs(userIDList, (AbstractUserStoreManager) userStoreManager);
        return doPreAddRole(roleName, userNames, permissions, userStoreManager);
    }

    private String[] getUserNamesFromUserIDs(String[] userIDList, AbstractUserStoreManager userStoreManager)
            throws UserStoreException {

        if (userIDList == null) {
            return new String[0];
        }
        List<String> userNamesList = userStoreManager.getUserNamesFromUserIDs(Arrays.asList(userIDList));
        return userNamesList.toArray(new String[0]);
    }

    @Override
    public boolean doPreDeleteRole(String roleName, UserStoreManager userStoreManager) throws UserStoreException {

        return true;
    }

    @Override
    public boolean doPreDeleteInternalRole(String roleName, UserStoreManager userStoreManager)
            throws UserStoreException {

        return doPreDeleteRole(roleName, userStoreManager);
    }

    @Override
    public boolean doPreUpdateRoleName(String roleName, String newRoleName, UserStoreManager userStoreManager) throws
            UserStoreException {
        return true;
    }

    @Override
    public boolean doPreUpdateInternalRoleName(String roleName, String newRoleName, UserStoreManager userStoreManager)
            throws UserStoreException {

        return doPreUpdateRoleName(roleName, newRoleName, userStoreManager);
    }

    @Override
    public boolean doPreUpdateUserListOfInternalRoleWithID(String roleName, String[] deletedUsersIDs, String[]
            newUsersIDs, UserStoreManager userStoreManager) throws UserStoreException {

        String[] newUserNames = getUserNamesFromUserIDs(newUsersIDs, (AbstractUserStoreManager) userStoreManager);
        String[] deletedUserNames = getUserNamesFromUserIDs(deletedUsersIDs,
                (AbstractUserStoreManager) userStoreManager);
        return doPreUpdateUserListOfRole(roleName, deletedUserNames, newUserNames, userStoreManager);
    }

    @Override
    public boolean doPreUpdateUserListOfRole(String roleName, String[] deletedUsers, String[] newUsers, UserStoreManager
            userStoreManager) throws UserStoreException {
        return true;
    }

    @Override
    public boolean doPreUpdateInternalRoleListOfUserWithID(String userID, String[] deletedRoles, String[] newRoles,
                                                           UserStoreManager userStoreManager)
            throws UserStoreException {

        String userName = ((AbstractUserStoreManager) userStoreManager).getUserNameFromUserID(userID);
        return doPreUpdateRoleListOfUser(userName, deletedRoles, newRoles, userStoreManager);
    }

    @Override
    public boolean doPreUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles, UserStoreManager
            userStoreManager) throws UserStoreException {
        return true;
    }

    private boolean isCalledViaIdentityMgtListners() {
        return IdentityUtil.threadLocalProperties.get().containsKey(DO_PRE_AUTHENTICATE_IDENTITY_PROPERTY) ||
                IdentityUtil .threadLocalProperties.get().containsKey(DO_POST_AUTHENTICATE_IDENTITY_PROPERTY) ||
                IdentityUtil .threadLocalProperties .get().containsKey(DO_POST_ADD_USER_IDENTITY_PROPERTY) ||
                IdentityUtil.threadLocalProperties.get() .containsKey(DO_PRE_SET_USER_CLAIM_VALUES_IDENTITY_PROPERT)
                || IdentityUtil.threadLocalProperties.get().containsKey (DO_POST_UPDATE_CREDENTIAL_IDENTITY_PROPERTY);
    }

    private void doPasswordPolicyValidation(String userName, Object credential, UserStoreManager userStoreManager)
            throws UserStoreException {

        String eventName = IdentityEventConstants.Event.VALIDATE_PASSWORD;
        String userTenantDomain = getUserTenantDomain(userStoreManager);
        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, userName);
        properties.put(IdentityEventConstants.EventProperty.CREDENTIAL, credential);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, userTenantDomain);
        // Publish password validation event.
        handleEvent(eventName, properties);
    }

    private String getUserTenantDomain(UserStoreManager userStoreManager) throws UserStoreException {

        int tenantId = userStoreManager.getTenantId();
        String userTenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            RealmService realmService = IdentityWorkflowDataHolder.getInstance().getRealmService();
            TenantManager tenantManager = realmService.getTenantManager();
            userTenantDomain = tenantManager.getDomain(tenantId);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            log.error("Unable to get the domain from realmService for tenant: " + tenantId, e);
        }
        return userTenantDomain;
    }

    private void handleEvent(String eventName, HashMap<String, Object> properties) throws UserStoreException {

        Event identityMgtEvent = new Event(eventName, properties);
        try {
            IdentityEventService eventService = IdentityWorkflowDataHolder.getInstance().getIdentityEventService();
            eventService.handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            String errorCode = e.getErrorCode();

            if (StringUtils.isNotEmpty(errorCode)) {
                if (PasswordPolicyConstants.ErrorMessages.ERROR_CODE_VALIDATING_PASSWORD_POLICY.getCode().
                        equals(errorCode) || PasswordPolicyConstants.ErrorMessages.
                        ERROR_CODE_LOADING_PASSWORD_POLICY_CLASSES.getCode().equals(errorCode)) {
                    throw new UserStoreException(e.getMessage(), e);
                }
            }
            throw new UserStoreException("Error when handling event : " + eventName, e);
        }
    }
}
