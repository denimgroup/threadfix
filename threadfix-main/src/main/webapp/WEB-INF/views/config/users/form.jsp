<script type="text/ng-template" id="userForm.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            {{ pageTitle }}
            <span ng-show="user.id" class="delete-span">
                <input class="btn btn-danger" id="delete{{ user.name }}" type="submit" value="Delete" ng-click="clickedDeleteButton()"/>
            </span>
        </h4>
    </div>

    <div ng-form="form" class="modal-body">
        <table class="modal-form-table dataTable">
            <tbody>
                <tr>
                    <td>User</td>
                    <td class="inputValue">
                        <input ng-model="user.name" required type="text" name="name"/>
                        <span class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                        <span class="errors" ng-show="user.name_error"> {{ user.name_error }}</span>
                    </td>
                </tr>
                <tr>
                    <td>Password</td>
                    <td class="inputValue">
                        <input password-validate="{{ user.passwordConfirm }}" ng-model="user.unencryptedPassword" required type="password" id="passwordInput" name="unencryptedPassword" size="30"/>
                        <span class="errors" ng-show="lengthRemaining">{{ lengthRemaining }} characters needed</span>
                        <span class="errors" ng-show="form.unencryptedPassword.$dirty && form.unencryptedPassword.$error.matches">Passwords do not match.</span>
                        <span class="errors" ng-show="form.unencryptedPassword.$dirty && form.unencryptedPassword.$error.required && !lengthRemaining">Password is required.</span>
                        <span class="errors" ng-show="user.password_error"> {{ user.password_error }}</span>
                    </td>
                </tr>
                <tr>
                    <td>Confirm Password</td>
                    <td class="inputValue">
                        <input ng-model="user.passwordConfirm" required type="password" style="margin-bottom:0px" id="passwordConfirmInput" name="passwordConfirm" size="30" />
                        <span class="errors" ng-show="form.passwordConfirm.$dirty && form.passwordConfirm.$error.required">Confirm Password is required.</span>
                    </td>
                </tr>
                <c:if test="${ ldap_plugin }">
                <tr>
                    <td class="no-color">LDAP user</td>
                    <td class="no-color" style="text-align: left;">
                        <input type="checkbox" class="ldapCheckbox"
                            id="isLdapUserCheckbox"
                            name="isLdapUser"
                            ng-model="user.isLdapUser"/>
                    </td>
                </tr>
                </c:if>
                <security:authorize ifAllGranted="ROLE_ENTERPRISE">
                <tr>
                    <td class="no-color">Global Access</td>
                    <td class="no-color" style="text-align: left;">
                        <input type="checkbox"
                            id="hasGlobalGroupAccessCheckbox"
                            class="globalAccessCheckBox"
                            name="hasGlobalGroupAccess"
                            ng-model="user.hasGlobalGroupAccess"/>
                    </td>
                </tr>
                <tr ng-show="user.hasGlobalGroupAccess">
                    <td class="no-color">Global Role</td>
                    <td class="no-color" style="text-align: left;">
                        <select id="roleSelect" name="globalRole.id" ng-model="user.globalRole.id">
                            <option value="0" label="Read Access" />
                            <option ng-selected="role.id === user.globalRole.id" ng-repeat="role in roles" value="{{ role.id }}">
                                {{ role.displayName }}
                            </option>
                        </select>
                    </td>
                    <td class="no-color" style="border: 0 solid black; background-color: white; padding-left: 5px">
                        <errors id="hasGlobalGroupAccessErrors" path="hasGlobalGroupAccess" cssClass="errors" />
                    </td>
                </tr>
                </security:authorize>
            </tbody>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
