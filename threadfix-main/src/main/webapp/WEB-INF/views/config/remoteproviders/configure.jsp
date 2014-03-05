<script type="text/ng-template" id="configureRemoteProviderModal.html">

    <div class="modal-header">
        <h4 id="myModalLabel">Configure {{ object.name }}</h4>
    </div>
    <div class="modal-body" ng-form="form">
        <table class="dataTable">
            <tbody>
                    <tr ng-show="object.hasUserNamePassword">
                        <td class="no-color">Username</td>
                        <td class="no-color inputValue">
                            <input focus-on="focusInput" ng-model="object.username" id="usernameInput" type="text" name="username" size="50" maxlength="60" style="width:420px" ng-required="object.hasUserNamePassword"/>
                        </td>
                    </tr>
                    <tr ng-show="object.hasUserNamePassword">
                        <td class="no-color">Password</td>
                        <td class="no-color inputValue">
                            <input ng-model="object.password" id="passwordInput" type="password" name="password" size="50" maxlength="60" ng-required="object.hasUserNamePassword" style="width:420px" />
                        </td>
                    </tr>
                    <tr ng-show="object.hasApiKey">
                        <td class="no-color">API Key</td>
                        <td class="no-color inputValue">
                            <input focus-on="focusInput" ng-model="object.apiKey" id="apiKeyInput" type="text" name="apiKey" ng-required="object.hasApiKey" size="50" maxlength="60" style="width:420px" />
                        </td>
                    </tr>
                    <tr ng-show="object.isQualys">
                        <td class="no-color">Region:</td>
                        <td class="no-color inputValue">
                            <input ng-model="object.isEuropean" type="radio" name="isEuropean" ng-value="false"> US </input>
                            <input ng-model="object.isEuropean" type="radio" name="isEuropean" ng-value="true"> EU </input>
                        </td>
                    </tr>
            </tbody>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>

</script>