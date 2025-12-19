package org.wso2.carbon.user.mgt.workflow.userstore;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
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
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.mgt.workflow.internal.IdentityWorkflowDataHolder;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The generic Data Provider for Workflow Rule Evaluations.
 */
public class WorkFlowRuleEvaluationDataProvider implements RuleEvaluationDataProvider {

    private static final String EMAIL_CLAIM_URI = "http://wso2.org/claims/emailaddress";

    @Override
    public FlowType getSupportedFlowType() {
        return FlowType.WORKFLOW_RULES;
    }

    @Override
    public List<FieldValue> getEvaluationData(RuleEvaluationContext ruleEvaluationContext, FlowContext flowContext,
                                              String tenantDomain) throws RuleEvaluationDataProviderException {

        List<FieldValue> fieldValues = new ArrayList<>();
        Map<String, Object> contextData = flowContext.getContextData();

        String roleId = (String) contextData.get("Role ID");
        if (StringUtils.isBlank(roleId)) {
            return fieldValues; // Cannot fetch data without ID
        }

        RoleBasicInfo roleBasicInfo = null;
        try {
            // Fetch Role Related Details using RoleManagementService
            RoleManagementService roleManagementService = IdentityWorkflowDataHolder.getInstance().getRoleManagementService();

            if (roleManagementService != null){
                roleBasicInfo = roleManagementService.getRoleBasicInfoById(roleId, tenantDomain);
            }
        } catch (IdentityRoleManagementException e){
            throw new RuleEvaluationDataProviderException("Error retrieving role info for roleId: " + roleId, e);
        }
        if (roleBasicInfo == null) {
            return fieldValues;
        }

        // Iterate through the fields required by the Rule
        for (Field field : ruleEvaluationContext.getFields()) {
            String fieldName = field.getName();

//            if ("grantType".equals(fieldName)) {
//                // Logic: Map grantType to Role Name (password role)
//                fieldValues.add(new FieldValue(fieldName, roleBasicInfo.getName(), ValueType.STRING));
//            } else if ("application".equals(fieldName)) {
//                // Logic: Map application(live as a ID in the DB) to Audience ID
//                String audienceId = roleBasicInfo.getAudienceId();
//                if (StringUtils.isNotBlank(audienceId)) {
//                    fieldValues.add(new FieldValue(fieldName, audienceId, ValueType.REFERENCE));
//                }
//            }

            if ("grantType".equals(fieldName)) {

                String extractedString = null;

                List<String> newUserIDList = (List<String>) contextData.get("newUsers");
                List<String> deletedUserIDList = (List<String>) contextData.get("deletedUsers");

                List<String> allUserIds = new ArrayList<>();
                if (CollectionUtils.isNotEmpty(newUserIDList)){
                    allUserIds.addAll(newUserIDList);
                }
                if (CollectionUtils.isNotEmpty(deletedUserIDList)){
                    allUserIds.addAll(deletedUserIDList);
                }

                if (CollectionUtils.isNotEmpty(allUserIds)) {
                    try {
                        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) CarbonContext
                                .getThreadLocalCarbonContext().getUserRealm().getUserStoreManager();

                        // iterate to find the first valid email
                        for (String userId : allUserIds) {
                            try {
                                Map<String, String> claims = userStoreManager.getUserClaimValuesWithID(
                                        userId,
                                        new String[]{EMAIL_CLAIM_URI},
                                        UserCoreConstants.DEFAULT_PROFILE
                                );

                                if (claims != null && claims.containsKey(EMAIL_CLAIM_URI)) {
                                    String email = claims.get(EMAIL_CLAIM_URI);

                                    // Perform the String Manipulation: fake@password.com -> password
                                    if (StringUtils.isNotBlank(email) && email.contains("@")) {
                                        String domainPart = email.substring(email.indexOf("@") + 1); // "password.com"
                                        if (domainPart.contains(".")) {
                                            extractedString = domainPart.substring(0, domainPart.lastIndexOf(".")); // "password"
                                            break; // found match, stop checking other users
                                        }
                                    }
                                }
                            } catch (UserStoreException e) {
                                // Ignore individual user failure
                            }
                        }
                    } catch (org.wso2.carbon.user.api.UserStoreException e) {
                        throw new RuleEvaluationDataProviderException("Error retrieving user store manager.", e);
                    }
                }

                if (StringUtils.isNotBlank(extractedString)) {
                    fieldValues.add(new FieldValue(fieldName, extractedString, ValueType.STRING));
                }

            } else if ("audience_id".equals(fieldName)) {
                String audienceId = roleBasicInfo.getAudienceId();
                if (StringUtils.isNotBlank(audienceId)) {
                    fieldValues.add(new FieldValue(fieldName, audienceId, ValueType.REFERENCE));
                }
            } else if ("role_name".equals(fieldName)) {
                String role_name = roleBasicInfo.getName();
                if (StringUtils.isNotBlank(role_name)){
                    fieldValues.add(new FieldValue(fieldName,role_name, ValueType.STRING) );
                }
            }
        }
        return fieldValues;
    }
}