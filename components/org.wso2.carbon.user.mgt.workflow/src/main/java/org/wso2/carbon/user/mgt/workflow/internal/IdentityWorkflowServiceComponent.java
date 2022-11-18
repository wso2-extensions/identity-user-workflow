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
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.user.core.listener.UserManagementErrorEventListener;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.mgt.workflow.userstore.UserStoreActionListener;
import org.wso2.carbon.utils.ConfigurationContextService;

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

    @Reference(name = "user.management.error.event.listener.service",
               service = org.wso2.carbon.user.core.listener.UserManagementErrorEventListener.class,
               cardinality = ReferenceCardinality.MULTIPLE,
               policy = ReferencePolicy.DYNAMIC,
               unbind = "unsetUserManagementErrorEventListenerService")
    protected synchronized void setUserManagementErrorEventListenerService(
            UserManagementErrorEventListener errorEventListenerService) {

        IdentityWorkflowDataHolder.getInstance()
                .addErrorEventListener(errorEventListenerService.getExecutionOrderId(), errorEventListenerService);
    }

    protected synchronized void unsetUserManagementErrorEventListenerService(
            UserManagementErrorEventListener errorEventListener) {

        IdentityWorkflowDataHolder.getInstance().removeErrorEventListener(errorEventListener.getExecutionOrderId());
    }

    @Reference(
            name = "EventMgtService",
            service = org.wso2.carbon.identity.event.services.IdentityEventService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityEventService")
    protected void setIdentityEventService(IdentityEventService identityEventService) {

        IdentityWorkflowDataHolder.getInstance().setIdentityEventService(identityEventService);
    }

    protected void unsetIdentityEventService(IdentityEventService identityEventService) {

        IdentityWorkflowDataHolder.getInstance().setIdentityEventService(null);
    }

    @Activate
    protected void activate(ComponentContext context) {

        BundleContext bundleContext = context.getBundleContext();
        bundleContext.registerService(UserOperationEventListener.class.getName(), new UserStoreActionListener(), null);;
        IdentityWorkflowDataHolder.getInstance().setBundleContext(bundleContext);
    }

    protected void unsetRealmService(RealmService realmService) {

        IdentityWorkflowDataHolder.getInstance().setRealmService(null);
    }

    protected void unsetConfigurationContextService(ConfigurationContextService contextService) {

        IdentityWorkflowDataHolder.getInstance().setConfigurationContextService(null);
    }
}
