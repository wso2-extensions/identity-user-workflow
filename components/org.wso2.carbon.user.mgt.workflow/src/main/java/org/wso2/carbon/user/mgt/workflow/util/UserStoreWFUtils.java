/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.user.mgt.workflow.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.listener.UserManagementErrorEventListener;
import org.wso2.carbon.user.mgt.workflow.internal.IdentityWorkflowDataHolder;
import org.wso2.carbon.utils.Secret;
import org.wso2.carbon.utils.UnsupportedSecretTypeException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.nio.CharBuffer;
import java.util.Map;
import java.util.regex.Pattern;

import static org.wso2.carbon.user.core.UserCoreConstants.RealmConfig.PROPERTY_JAVA_REG_EX;
import static org.wso2.carbon.user.core.UserCoreConstants.RealmConfig.PROPERTY_USER_NAME_JAVA_REG;
import static org.wso2.carbon.user.core.UserCoreConstants.RealmConfig.PROPERTY_USER_NAME_JAVA_REG_EX;
import static org.wso2.carbon.user.core.UserCoreConstants.RealmConfig.PROPERTY_USER_NAME_WITH_EMAIL_JS_REG_EX;

/**
 * User store utils for workflow.
 */
public class UserStoreWFUtils {

    private static final Log log = LogFactory.getLog(UserStoreWFUtils.class);

    /**
     * Check whether the username is valid.
     *
     * @param username    user name
     * @param realmConfig realm configuration
     * @return validation result
     */
    public static ValidationResult isUsernameValid(String username, RealmConfiguration realmConfig) {

        String usernameRegEx = getUsernameRegEx(realmConfig);

        if (StringUtils.isBlank(username) || CarbonConstants.REGISTRY_SYSTEM_USERNAME.equals(username)) {
            return new ValidationResult(false, usernameRegEx);
        }

        if (StringUtils.isBlank(usernameRegEx)) {
            return new ValidationResult(true);
        }

        if (Pattern.compile(usernameRegEx.trim()).matcher(username).matches()) {
            return new ValidationResult(true);
        }

        if (log.isDebugEnabled()) {
            log.debug("Username: " + username + " does not match with the regex: " + usernameRegEx);
        }

        return new ValidationResult(false, usernameRegEx);
    }

    private static String getUsernameRegEx(RealmConfiguration realmConfig) {

        if (MultitenantUtils.isEmailUserName()) {

            if (StringUtils.isNotBlank(realmConfig.getUserStoreProperty(PROPERTY_USER_NAME_WITH_EMAIL_JS_REG_EX))) {
                return realmConfig.getUserStoreProperty(PROPERTY_USER_NAME_WITH_EMAIL_JS_REG_EX);
            }

            if (StringUtils.isBlank(realmConfig.getUserStoreProperty(PROPERTY_USER_NAME_JAVA_REG_EX)) && StringUtils
                    .isBlank(PROPERTY_USER_NAME_JAVA_REG)) {
                return UserCoreConstants.RealmConfig.EMAIL_VALIDATION_REGEX;
            }
        }

        if (StringUtils.isNotBlank(realmConfig.getUserStoreProperty(PROPERTY_USER_NAME_JAVA_REG_EX))) {
            return realmConfig.getUserStoreProperty(PROPERTY_USER_NAME_JAVA_REG_EX);
        }

        if (StringUtils.isNotBlank(realmConfig.getUserStoreProperty(PROPERTY_USER_NAME_JAVA_REG))) {
            return realmConfig.getUserStoreProperty(PROPERTY_USER_NAME_JAVA_REG);
        }

        return null;
    }

    /**
     * Check whether the password is valid.
     *
     * @param credential  credential
     * @param realmConfig realm configuration
     * @return validation result
     * @throws UserStoreException if validation error
     */
    public static ValidationResult isPasswordValid(Object credential, RealmConfiguration realmConfig)
            throws UserStoreException {

        String passwordRegEx = realmConfig.getUserStoreProperty(PROPERTY_JAVA_REG_EX);

        if (credential == null) {
            return new ValidationResult(false, passwordRegEx);
        }

        Secret credentialObj;
        try {
            credentialObj = Secret.getSecret(credential.toString());
        } catch (UnsupportedSecretTypeException e) {
            throw new UserStoreException("Unsupported credential type", e);
        }

        try {
            if (credentialObj.getChars().length < 1) {
                return new ValidationResult(false, passwordRegEx);
            }

            if (StringUtils.isBlank(passwordRegEx)) {
                return new ValidationResult(true);
            }

            if (Pattern.compile(passwordRegEx.trim()).matcher(CharBuffer.wrap(credentialObj.getChars())).matches()) {
                return new ValidationResult(true);
            }

            if (log.isDebugEnabled()) {
                log.debug("Submitted password does not match with the regex: " + passwordRegEx);
            }

            return new ValidationResult(false, passwordRegEx);
        } finally {
            credentialObj.clear();
        }
    }

    /**
     * Trigger add user failure listeners.
     *
     * @param errorCode        error code
     * @param errorMessage     error message
     * @param username         username
     * @param credential       credential
     * @param roleList         role list
     * @param claims           claims
     * @param profile          profile
     * @param userStoreManager user store manager
     * @throws UserStoreException if error listener fails
     */
    public static void triggerAddUserFailureListeners(String errorCode, String errorMessage, String username,
            Object credential, String[] roleList, Map<String, String> claims, String profile,
            UserStoreManager userStoreManager) throws UserStoreException {

        for (UserManagementErrorEventListener listener : IdentityWorkflowDataHolder.getInstance()
                .getErrorEventListeners()) {

            if (listener.isEnable() && !listener
                    .onAddUserFailure(errorCode, errorMessage, username, credential, roleList, claims, profile,
                            userStoreManager)) {
                return;
            }
        }
    }
}
