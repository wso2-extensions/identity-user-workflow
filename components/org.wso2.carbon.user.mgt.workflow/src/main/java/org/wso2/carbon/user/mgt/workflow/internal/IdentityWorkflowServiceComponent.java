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
package org.wso2.carbon.user.mgt.workflow.internal;

import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.workflow.mgt.WorkflowManagementService;
import org.wso2.carbon.identity.workflow.mgt.extension.WorkflowRequestHandler;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.mgt.workflow.userstore.AddRoleWFRequestHandler;
import org.wso2.carbon.user.mgt.workflow.userstore.AddUserWFRequestHandler;
import org.wso2.carbon.user.mgt.workflow.userstore.DeleteMultipleClaimsWFRequestHandler;
import org.wso2.carbon.user.mgt.workflow.userstore.DeleteRoleWFRequestHandler;
import org.wso2.carbon.user.mgt.workflow.userstore.DeleteUserWFRequestHandler;
import org.wso2.carbon.user.mgt.workflow.userstore.SetMultipleClaimsWFRequestHandler;
import org.wso2.carbon.user.mgt.workflow.userstore.UpdateRoleNameWFRequestHandler;
import org.wso2.carbon.user.mgt.workflow.userstore.UpdateRoleUsersWFRequestHandler;
import org.wso2.carbon.user.mgt.workflow.userstore.UpdateUserRolesWFRequestHandler;
import org.wso2.carbon.user.mgt.workflow.userstore.UserStoreActionListener;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

@Component(
         name = "identity.workflow", 
         immediate = true)
public class IdentityWorkflowServiceComponent {

    @Reference(
             name = "user.realmservice.default", 
             service = org.wso2.carbon.user.core.service.RealmService.class, 
             cardinality = ReferenceCardinality.MANDATORY, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {
        IdentityWorkflowDataHolder.getInstance().setRealmService(realmService);
    }

    @Reference(
             name = "config.context.service", 
             service = org.wso2.carbon.utils.ConfigurationContextService.class, 
             cardinality = ReferenceCardinality.MANDATORY, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetConfigurationContextService")
    protected void setConfigurationContextService(ConfigurationContextService contextService) {
        IdentityWorkflowDataHolder.getInstance().setConfigurationContextService(contextService);
    }

    @Reference(
             name = "workflowservice.default", 
             service = org.wso2.carbon.identity.workflow.mgt.WorkflowManagementService.class, 
             cardinality = ReferenceCardinality.MANDATORY, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetWorkflowService")
    protected void setWorkflowService(WorkflowManagementService workflowService) {
        IdentityWorkflowDataHolder.getInstance().setWorkflowService(workflowService);
    }

    @Activate
    protected void activate(ComponentContext context) {
        BundleContext bundleContext = context.getBundleContext();
        bundleContext.registerService(UserOperationEventListener.class.getName(), new UserStoreActionListener(), null);
        bundleContext.registerService(WorkflowRequestHandler.class.getName(), new AddUserWFRequestHandler(), null);
        bundleContext.registerService(WorkflowRequestHandler.class.getName(), new AddRoleWFRequestHandler(), null);
        bundleContext.registerService(WorkflowRequestHandler.class.getName(), new DeleteUserWFRequestHandler(), null);
        bundleContext.registerService(WorkflowRequestHandler.class.getName(), new DeleteRoleWFRequestHandler(), null);
        // todo: commenting out for a test failure
        // bundleContext.registerService(WorkflowRequestHandler.class.getName(), new ChangeCredentialWFRequestHandler(),
        // null);
        bundleContext.registerService(WorkflowRequestHandler.class.getName(), new DeleteMultipleClaimsWFRequestHandler(), null);
        bundleContext.registerService(WorkflowRequestHandler.class.getName(), new SetMultipleClaimsWFRequestHandler(), null);
        bundleContext.registerService(WorkflowRequestHandler.class.getName(), new UpdateUserRolesWFRequestHandler(), null);
        bundleContext.registerService(WorkflowRequestHandler.class.getName(), new UpdateRoleUsersWFRequestHandler(), null);
        bundleContext.registerService(WorkflowRequestHandler.class.getName(), new UpdateRoleNameWFRequestHandler(), null);
        IdentityWorkflowDataHolder.getInstance().setBundleContext(bundleContext);
    }

    protected void unsetRealmService(RealmService realmService) {
        IdentityWorkflowDataHolder.getInstance().setRealmService(null);
    }

    protected void unsetConfigurationContextService(ConfigurationContextService contextService) {
        IdentityWorkflowDataHolder.getInstance().setConfigurationContextService(null);
    }

    protected void unsetWorkflowService(WorkflowManagementService workflowService) {
        IdentityWorkflowDataHolder.getInstance().setWorkflowService(null);
    }
}

