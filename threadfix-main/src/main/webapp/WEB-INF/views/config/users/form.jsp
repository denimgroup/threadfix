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
                        <input ng-model="user.name" required type="text"/>
                        <span class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                    </td>
                </tr>
                <tr>
                    <td>Password</td>
                    <td class="inputValue">
                        <input password-validate="{{ user.passwordConfirm }}" ng-model="user.unencryptedPassword" required type="password" id="passwordInput" name="unencryptedPassword" size="30"/>
                        <span class="errors" ng-show="lengthRemaining">{{ lengthRemaining }} characters needed</span>
                        <span class="errors" ng-show="form.unencryptedPassword.$dirty && form.unencryptedPassword.$error.matches">Passwords do not match.</span>
                    </td>
                </tr>
                <tr>
                    <td>Confirm Password</td>
                    <td class="inputValue">
                        <input ng-model="user.passwordConfirm" required type="password" style="margin-bottom:0px" id="passwordConfirmInput" name="passwordConfirm" size="30" />
                        <span class="errors" ng-show="form.passwordConfirm.$dirty && form.passwordConfirm.$error.required">This field is required.</span>
                    </td>
                </tr>
                <c:if test="${ ldap_plugin }">
                <tr>
                    <td class="no-color">LDAP user</td>
                    <td class="no-color" style="text-align: left;">
                        <checkbox class="ldapCheckbox"
                            data-target-class="password${ status.count }"
                            id="isLdapUserCheckbox${ status.count }"
                            path="isLdapUser"
                            data-value="${user.isLdapUser}" />
                    </td>
                </tr>
                </c:if>
                <security:authorize ifAllGranted="ROLE_ENTERPRISE">
                <tr>
                    <td class="no-color">Global Access</td>
                    <td class="no-color" style="text-align: left;">
                        <checkbox onclick="toggleRoles('${ status.count }')"
                            id="hasGlobalGroupAccessCheckbox${ status.count }"
                            class="globalAccessCheckBox"
                            path="hasGlobalGroupAccess"
                            data-value="${user.hasGlobalGroupAccess}"/>
                    </td>
                </tr>
                <tr>
                    <td class="no-color">Role for Global Access</td>
                    <td class="no-color" style="text-align: left;">
                        <select id="roleSelect${ status.count }" path="globalRole.id">
                            <option value="0" label="Read Access" />
                            <options items="${ roleList }" itemValue="id" itemLabel="displayName" />
                        </select>

                        <!-- TODO enterprise this shit up -->
                        <%--<c:if test="${ not user.hasGlobalGroupAccess }">--%>
                            <%--<script>$("#roleSelect<c:out value='${ status.count }'/>").attr("disabled","disabled");</script>--%>
                        <%--</c:if>--%>
                        <%--<c:if test="${ user.hasGlobalGroupAccess }">--%>
                            <%--<script>$("#roleSelect<c:out value='${ status.count }'/>").val(<c:out value='${ user.globalRole.id }'/>);</script>--%>
                        <%--</c:if>--%>
                        <%--<c:if test="${ empty user.globalRole }">--%>
                            <%--<script>$("#roleSelect<c:out value='${ status.count }'/>").val(0);</script>--%>
                        <%--</c:if>--%>
                    </td>
                    <td class="no-color" style="border: 0px solid black; background-color: white; padding-left: 5px">
                        <errors id="hasGlobalGroupAccessErrors${ status.count }" path="hasGlobalGroupAccess" cssClass="errors" />
                    </td>
                </tr>
                </security:authorize>
            </tbody>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>