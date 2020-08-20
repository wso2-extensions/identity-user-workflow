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

/**
 * This class represents the regular expresion validation result.
 */
public class ValidationResult {

    private boolean valid;

    private String regExUsed;

    public ValidationResult(boolean valid) {

        this.valid = valid;
    }

    public ValidationResult(boolean valid, String regExUsed) {

        this.valid = valid;
        this.regExUsed = regExUsed;
    }

    public boolean isValid() {

        return valid;
    }

    public void setValid(boolean valid) {

        this.valid = valid;
    }

    public String getRegExUsed() {

        return regExUsed;
    }

    public void setRegExUsed(String regExUsed) {

        this.regExUsed = regExUsed;
    }
}
