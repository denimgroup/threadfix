<script type="text/ng-template" id="configureRemoteProviderModal.html">

    <div class="modal-header">
        <h4 id="myModalLabel">Configure {{ object.name }}</h4>
    </div>
    <div class="modal-body" ng-form="form">
        <table class="dataTable">
            <tbody ng-if="object.authenticationFields.length === 0">
                <tr ng-if="object.hasUserNamePassword">
                    <td class="no-color">Username</td>
                    <td class="no-color inputValue">
                        <input focus-on="focusInput" ng-model="object.username" id="usernameInput" type="text" name="username" size="50" maxlength="60" ng-required="object.hasUserNamePassword" style="width:280px"/>
                    </td>
                    <td>
                        <span class="errors" ng-show="object.hasUserNamePassword && form.username.$dirty && form.username.$error.required">Username is required.</span>
                        <span class="errors" ng-show="form.username.$dirty && form.username.$error.maxlength">Over 60 characters limit!</span>
                    </td>
                </tr>
                <tr ng-if="object.hasUserNamePassword">
                    <td class="no-color">Password</td>
                    <td class="no-color inputValue">
                        <input ng-model="object.password" id="passwordInput" type="password" name="password" size="50" maxlength="60" ng-required="object.hasUserNamePassword" style="width:280px"/>
                    </td>
                    <td>
                        <span class="errors" ng-show="object.hasUserNamePassword && form.password.$dirty && form.password.$error.required">Password is required.</span>
                        <span class="errors" ng-show="form.password.$dirty && form.password.$error.maxlength">Over 60 characters limit!</span>
                    </td>
                </tr>
                <tr ng-if="object.hasApiKey">
                    <td class="no-color">API Key</td>
                    <td class="no-color inputValue">
                        <input focus-on="focusInput" ng-model="object.apiKey" id="apiKeyInput" type="password" name="apiKey" ng-pattern="/^[a-zA-Z0-9-]*$/" ng-required="object.hasApiKey" size="50" maxlength="60" style="width:280px"/>
                    </td>
                    <td>
                        <span class="errors" ng-show="object.hasApiKey && form.apiKey.$dirty && form.apiKey.$error.required">API Key is required.</span>
                        <span class="errors" ng-show="form.apiKey.$dirty && form.apiKey.$error.maxlength">Over 60 characters limit!</span>
                        <span class="errors" ng-show="form.apiKey.$dirty && form.apiKey.$error.pattern">Invalid characters, only alphanum / hyphen.</span>
                    </td>
                </tr>
                <tr ng-if="object.isQualys">
                    <td align="left" class="no-color">Platform</td>
                    <td align="left" class="no-color inputValue">
                        <select ng-model="object.platform" id="platformNameSelect" name="platform">
                            <option ng-repeat="qualysPlatform in config.qualysPlatforms"
                                    ng-selected="object.platform === qualysPlatform"
                                    value="{{ qualysPlatform }}">
                                {{ qualysPlatform }}
                            </option>
                        </select>
                    </td>
                </tr>
            </tbody>
            <tbody ng-if="object.authenticationFields.length !== 0">
                <tr ng-repeat="field in object.authenticationFields">
                    <td class="no-color">{{ field.name }}</td>
                    <td class="no-color inputValue">
                        <input ng-if="field.secret" type="password"
                               focus-on="$index === 0"
                               ng-model="field.value"
                               id="{{ field.name | removeSpace }}"
                               name="username" size="50" maxlength="60" ng-required="field.required" style="width:280px"/>
                        <input ng-if="!field.secret" type="text"
                               focus-on="$index === 0"
                               ng-model="field.value" id="{{ field.name | removeSpace }}"
                               placeholder="{{field.placeholder}}"
                               name="username" size="50" maxlength="60" ng-required="field.required" style="width:280px"/>
                    </td>
                    <td>
                        <span class="errors" ng-show="form.username.$dirty && form.username.$error.required">{{ field.name }} is required.</span>
                        <span class="errors" ng-show="form.username.$dirty && form.username.$error.maxlength">Over 60 characters limit!</span>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>

</script>