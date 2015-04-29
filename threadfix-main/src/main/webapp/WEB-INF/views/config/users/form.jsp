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
                    <td>Username</td>
                    <td class="inputValue">
                        <input ng-model="user.name" required type="text" name="name" id="name"/>
                        <span id="name.errors.required" class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                        <span id="name.errors" class="errors" ng-show="user.name_error"> {{ user.name_error }}</span>
                    </td>
                </tr>
                <tr>
                    <td>Display Name</td>
                    <td class="inputValue">
                        <input ng-model="user.displayName" type="text" name="displayName" id="displayName"/>
                        <span id="displayName.errors" class="errors" ng-show="user.name_error"> {{ user.name_error }}</span>
                    </td>
                </tr>
                <tr ng-if="!user.isLdapUser">
                    <td>Password</td>
                    <td class="inputValue">
                        <input password-validate="{{ user.passwordConfirm }}" id="password" ng-model="user.unencryptedPassword" required type="password" id="passwordInput" name="unencryptedPassword" size="30"/>
                        <span id="password.error.length" class="errors" ng-show="lengthRemaining">{{ lengthRemaining }} characters needed</span>
                        <span id="password.error.match" class="errors" ng-show="form.unencryptedPassword.$dirty && form.unencryptedPassword.$error.matches">Passwords do not match.</span>
                        <span id="password.error.required" class="errors" ng-show="form.unencryptedPassword.$dirty && form.unencryptedPassword.$error.required && !lengthRemaining">Password is required.</span>
                        <span id="password.error" class="errors" ng-show="user.password_error"> {{ user.password_error }}</span>
                    </td>
                </tr>
                <tr ng-if="!user.isLdapUser">
                    <td>Confirm Password</td>
                    <td class="inputValue">
                        <input ng-model="user.passwordConfirm" id="confirm" required type="password" style="margin-bottom:0" id="passwordConfirmInput" name="passwordConfirm" size="30" />
                        <span class="errors" id="confirmPassword.error" ng-show="form.passwordConfirm.$dirty && form.passwordConfirm.$error.required">Confirm Password is required.</span>
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
            </tbody>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
