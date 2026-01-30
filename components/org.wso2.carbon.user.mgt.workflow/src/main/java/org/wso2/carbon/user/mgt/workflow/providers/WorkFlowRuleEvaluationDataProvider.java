package org.wso2.carbon.user.mgt.workflow.providers;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;
import org.wso2.carbon.identity.rule.evaluation.api.exception.RuleEvaluationDataProviderException;
import org.wso2.carbon.identity.rule.evaluation.api.model.Field;
import org.wso2.carbon.identity.rule.evaluation.api.model.FieldValue;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowContext;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowType;
import org.wso2.carbon.identity.rule.evaluation.api.model.RuleEvaluationContext;
import org.wso2.carbon.identity.rule.evaluation.api.model.ValueType;
import org.wso2.carbon.identity.rule.evaluation.api.provider.RuleEvaluationDataProvider;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.mgt.workflow.internal.IdentityWorkflowDataHolder;
import org.wso2.carbon.user.mgt.workflow.util.UserStoreWFConstants;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * The unified Data Provider for Workflow Rule Evaluations across all workflow event types.
 */
public class WorkFlowRuleEvaluationDataProvider implements RuleEvaluationDataProvider {

    private static final Log log = LogFactory.getLog(WorkFlowRuleEvaluationDataProvider.class);

    // Claim URI prefix.
    private static final String WSO2_CLAIM_URI_PREFIX = "http://wso2.org/claims/";

    /**
     * Enum for supported non-claim rule fields in workflow operations.
     */
    private enum RuleField {
        USER_DOMAIN("user.domain"),
        ROLE_NAME("role.name"),
        ROLE_AUDIENCE_ID("audience.id"),
        ROLE_ID("role.id"),
        USER_ROLES("user.roles"),
        USER_GROUPS("user.groups");

        private final String fieldName;

        RuleField(String fieldName) {
            this.fieldName = fieldName;
        }

        public String getFieldName() {
            return fieldName;
        }

        /**
         * Get RuleField from field name if it's a known non-claim field.
         *
         * @param fieldName Field name.
         * @return RuleField if found, null otherwise.
         */
        public static RuleField valueOfFieldName(String fieldName) {
            for (RuleField ruleField : RuleField.values()) {
                if (ruleField.getFieldName().equals(fieldName)) {
                    return ruleField;
                }
            }
            return null;
        }
    }

    /**
     * Check if a field name is a claim URI.
     *
     * @param fieldName Field name to check.
     * @return True if the field name is a claim URI.
     */
    private boolean isClaimUri(String fieldName) {
        return fieldName != null && fieldName.startsWith(WSO2_CLAIM_URI_PREFIX);
    }

    @Override
    public FlowType getSupportedFlowType() {
        return FlowType.APPROVAL_WORKFLOW;
    }

    @Override
    public List<FieldValue> getEvaluationData(RuleEvaluationContext ruleEvaluationContext, FlowContext flowContext,
                                              String tenantDomain) throws RuleEvaluationDataProviderException {

        List<FieldValue> fieldValues = new ArrayList<>();
        Map<String, Object> contextData = flowContext.getContextData();

        if (log.isDebugEnabled()) {
            log.debug("Processing workflow rule evaluation for tenant: " + tenantDomain +
                     " with event type: " + contextData.get("eventType"));
        }

        // Iterate through the fields required by the Rule.
        for (Field field : ruleEvaluationContext.getFields()) {
            String fieldName = field.getName();

            try {
                // First check if the field is a claim URI.
                if (isClaimUri(fieldName)) {
                    addUserClaimFieldValue(fieldValues, field, contextData, fieldName, tenantDomain);
                    continue;
                }

                // Handle non-claim fields.
                RuleField ruleField = RuleField.valueOfFieldName(fieldName);
                if (ruleField == null) {
                    throw new RuleEvaluationDataProviderException("Unsupported field: " + fieldName);
                }

                switch (ruleField) {
                    case USER_DOMAIN:
                        addUserDomainFieldValue(fieldValues, field, contextData);
                        break;
                    case ROLE_AUDIENCE_ID:
                        addRoleAudienceIdFieldValue(fieldValues, field, contextData, tenantDomain);
                        break;
                    case ROLE_ID:
                        addRoleIdFieldValue(fieldValues, field, contextData);
                        break;
                    case USER_ROLES:
                        addUserRolesFieldValue(fieldValues, field, contextData, tenantDomain);
                        break;
                    case USER_GROUPS:
                        addUserGroupsFieldValue(fieldValues, field, contextData, tenantDomain);
                        break;
                    default:
                        throw new RuleEvaluationDataProviderException("Unsupported field by WF rule evaluation data provider: " + fieldName);
                }
            } catch (RuleEvaluationDataProviderException e) {
                // Re-throw as is.
                throw e;
            } catch (Exception e) {
                throw new RuleEvaluationDataProviderException("Error processing field: " + fieldName, e);
            }
        }

        return fieldValues;
    }

    /**
     * Add user domain field value from context data.
     */
    private void addUserDomainFieldValue(List<FieldValue> fieldValues, Field field, Map<String, Object> contextData) {
        String userStoreDomain = (String) contextData.get("User Store Domain");
        if (StringUtils.isNotBlank(userStoreDomain)) {
            fieldValues.add(new FieldValue(field.getName(), userStoreDomain, ValueType.STRING));
        }
    }

    /**
     * Add role ID field value from context data.
     */
    private void addRoleIdFieldValue(List<FieldValue> fieldValues, Field field, Map<String, Object> contextData) {
        String roleId = (String) contextData.get("Role ID");
        if (StringUtils.isNotBlank(roleId)) {
            fieldValues.add(new FieldValue(field.getName(), roleId, ValueType.STRING));
        }
    }

    /**
     * Add user role field value from context data or fetch from user store.
     */
    private void addUserRolesFieldValue(List<FieldValue> fieldValues, Field field, Map<String, Object> contextData,
                                       String tenantDomain) throws RuleEvaluationDataProviderException {

        String username = (String) contextData.get("Username");
        try {
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) CarbonContext
                    .getThreadLocalCarbonContext().getUserRealm().getUserStoreManager();

            String[] roleArray = userStoreManager.getRoleListOfUser(username);
            if (roleArray != null && roleArray.length > 0) {
                List<String> roleList = Arrays.asList(roleArray);
                fieldValues.add(new FieldValue(field.getName(), roleList.toString(), ValueType.LIST));
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new RuleEvaluationDataProviderException(
                    "Error retrieving roles for username: " + username, e);
        }
    }

    /**
     * Add user groups field value from context data or fetch from user store.
     */
    private void addUserGroupsFieldValue(List<FieldValue> fieldValues, Field field, Map<String, Object> contextData,
                                        String tenantDomain) throws RuleEvaluationDataProviderException {

        String username = (String) contextData.get("Username");

        try {
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) CarbonContext
                    .getThreadLocalCarbonContext().getUserRealm().getUserStoreManager();

            // Get user ID first for getGroupListOfUser.
            String userId = userStoreManager.getUserIDFromUserName(username);
            if (StringUtils.isBlank(userId)) {
                if (log.isDebugEnabled()) {
                    log.debug("Could not resolve user ID for username: " + username);
                }
                return;
            }

            List<org.wso2.carbon.user.core.common.Group> groupList =
                    userStoreManager.getGroupListOfUser(userId, null, null);
            if (CollectionUtils.isNotEmpty(groupList)) {
                List<String> groupNames = new ArrayList<>();
                for (org.wso2.carbon.user.core.common.Group group : groupList) {
                    groupNames.add(group.getGroupName());
                }
                fieldValues.add(new FieldValue(field.getName(), groupNames.toString(), ValueType.LIST));
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new RuleEvaluationDataProviderException(
                    "Error retrieving groups for username: " + username, e);
        }
    }

    /**
     * Add user claim field value by fetching from user store.
     * First checks if the claim value is available in context data, otherwise fetches from user store.
     */
    private void addUserClaimFieldValue(List<FieldValue> fieldValues, Field field, Map<String, Object> contextData,
                                       String claimUri, String tenantDomain)
                                       throws RuleEvaluationDataProviderException {

        // First try to get the claim value directly from context data.
        String claimValue = (String) contextData.get(claimUri);
        if (StringUtils.isNotBlank(claimValue)) {
            fieldValues.add(new FieldValue(field.getName(), claimValue, ValueType.STRING));
            return;
        }

        // If not in context, fetch from user store using username.
        String username = (String) contextData.get("Username");
        if (StringUtils.isBlank(username)) {
            if (log.isDebugEnabled()) {
                log.debug("Cannot fetch claim " + claimUri + " without Username in context.");
            }
            return;
        }

        try {
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) CarbonContext
                    .getThreadLocalCarbonContext().getUserRealm().getUserStoreManager();

            Map<String, String> claims = userStoreManager.getUserClaimValues(
                    username,
                    new String[]{claimUri},
                    UserCoreConstants.DEFAULT_PROFILE
            );

            if (claims != null && claims.containsKey(claimUri)) {
                claimValue = claims.get(claimUri);
                if (StringUtils.isNotBlank(claimValue)) {
                    fieldValues.add(new FieldValue(field.getName(), claimValue, ValueType.STRING));
                }
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new RuleEvaluationDataProviderException(
                    "Error retrieving user claim " + claimUri + " for username: " + username, e);
        }
    }

    /**
     * Add role audience ID field value by fetching from role management service.
     */
    private void addRoleAudienceIdFieldValue(List<FieldValue> fieldValues, Field field, Map<String, Object> contextData,
                                            String tenantDomain) throws RuleEvaluationDataProviderException {

        // First check if role audience ID is already available in context data.
        String roleAudienceId = (String) contextData.get("Role Audience ID");
        if (StringUtils.isNotBlank(roleAudienceId)) {
            fieldValues.add(new FieldValue(field.getName(), roleAudienceId, ValueType.REFERENCE));
            return;
        }

        // If not in context, fetch using Role ID from RoleManagementService.
        String roleId = (String) contextData.get("Role ID");
        if (StringUtils.isBlank(roleId)) {
            log.debug("Cannot fetch role audience ID without Role ID in context.");
            return;
        }

        RoleBasicInfo roleBasicInfo = null;
        try {
            // Fetch Role Related Details using RoleManagementService.
            RoleManagementService roleManagementService = IdentityWorkflowDataHolder.getInstance()
                    .getRoleManagementService();

            if (roleManagementService != null) {
                roleBasicInfo = roleManagementService.getRoleBasicInfoById(roleId, tenantDomain);
            }
        } catch (IdentityRoleManagementException e) {
            throw new RuleEvaluationDataProviderException("Error retrieving role info for roleId: " + roleId, e);
        }

        if (roleBasicInfo != null && StringUtils.isNotBlank(roleBasicInfo.getAudienceId())) {
            fieldValues.add(new FieldValue(field.getName(), roleBasicInfo.getAudienceId(), ValueType.REFERENCE));
        }
    }
}