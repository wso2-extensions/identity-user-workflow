package org.wso2.carbon.user.mgt.workflow.userstore;

import org.wso2.carbon.identity.rule.evaluation.api.exception.RuleEvaluationDataProviderException;
import org.wso2.carbon.identity.rule.evaluation.api.model.Field;
import org.wso2.carbon.identity.rule.evaluation.api.model.FieldValue;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowContext;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowType;
import org.wso2.carbon.identity.rule.evaluation.api.model.RuleEvaluationContext;
import org.wso2.carbon.identity.rule.evaluation.api.model.ValueType;
import org.wso2.carbon.identity.rule.evaluation.api.provider.RuleEvaluationDataProvider;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Data Provider for Role Update Rule Evaluation.
 */
public class UpdateRoleRuleEvaluationDataProvider implements RuleEvaluationDataProvider {

    @Override
    public FlowType getSupportedFlowType() {
        return FlowType.PRE_UPDATE_ROLE;
    }

    @Override
    public List<FieldValue> getEvaluationData(RuleEvaluationContext ruleEvaluationContext, FlowContext flowContext,
                                              String tenantDomain) throws RuleEvaluationDataProviderException {

        List<FieldValue> fieldValues = new ArrayList<>();
        Map<String, Object> contextData = flowContext.getContextData();

        // Iterate through the fields required by the Rule (Rule ID 11 needs 'grantType')
        for (Field field : ruleEvaluationContext.getFields()) {
            String fieldName = field.getName();

            // The Hack: Check if the rule is asking for a field we manually put in the context
            if (contextData.containsKey(fieldName)) {
                Object value = contextData.get(fieldName);
                // Assuming the value is a String for this test case
                fieldValues.add(new FieldValue(fieldName, value.toString(), ValueType.STRING));
            }
        }
        return fieldValues;
    }
}