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

package org.wso2.carbon.user.mgt.workflow.internal;

import org.osgi.framework.BundleContext;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.workflow.mgt.WorkflowManagementService;
import org.wso2.carbon.user.core.listener.UserManagementErrorEventListener;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.util.Collection;
import java.util.Map;
import java.util.TreeMap;

/**
 * Identity workflow data holder class.
 */
public class IdentityWorkflowDataHolder {

    private static IdentityWorkflowDataHolder instance = new IdentityWorkflowDataHolder();

    private RealmService realmService;
    private ConfigurationContextService configurationContextService;
    private BundleContext bundleContext;
    private WorkflowManagementService workflowService;
    private IdentityEventService identityEventService;
    private RoleManagementService roleManagementService;
    private Map<Integer, UserManagementErrorEventListener> errorEventListenerMap =  new TreeMap<>();

    public static IdentityWorkflowDataHolder getInstance() {

        return instance;
    }

    private IdentityWorkflowDataHolder() {

    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public ConfigurationContextService getConfigurationContextService() {

        return configurationContextService;
    }

    public void setConfigurationContextService(
            ConfigurationContextService configurationContextService) {

        this.configurationContextService = configurationContextService;
    }

    public BundleContext getBundleContext() {

        return bundleContext;
    }

    public void setBundleContext(BundleContext bundleContext) {

        this.bundleContext = bundleContext;
    }

    public WorkflowManagementService getWorkflowService() {
        return workflowService;
    }

    public void setWorkflowService(WorkflowManagementService workflowService) {
        this.workflowService = workflowService;
    }

    public Collection<UserManagementErrorEventListener> getErrorEventListeners() {

        return errorEventListenerMap.values();
    }

    public void addErrorEventListener(Integer executionOder, UserManagementErrorEventListener errorEventListener) {

        this.errorEventListenerMap.put(executionOder, errorEventListener);
    }

    public void removeErrorEventListener(Integer executionOder) {

        this.errorEventListenerMap.remove(executionOder);
    }

    public IdentityEventService getIdentityEventService() {

        if (identityEventService == null) {
            throw new RuntimeException("IdentityEventService was not set during the IdentityWorkflowService " +
                    "component startup.");
        }
        return identityEventService;
    }

    public void setIdentityEventService(IdentityEventService eventMgtService) {

        this.identityEventService = eventMgtService;
    }

    public RoleManagementService getRoleManagementService() {

        return roleManagementService;
    }

    public void setRoleManagementService(RoleManagementService roleManagementService) {

        this.roleManagementService = roleManagementService;
    }
}
