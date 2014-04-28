<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Password Change</title>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/focus-controller.js"></script>
</head>

<body id="config">
	<h2>User Password Change</h2>

    <div ng-controller="FocusController" ng-init="focus()">
        <c:if test="${ not empty successMessage }">
            <div ng-hide="hideAlert" class="alert alert-success">
                <button class="close" ng-click="hideAlert = true" type="button">x</button>
                <c:out value="${ successMessage }"/>
            </div>
        </c:if>
        <%@ include file="/WEB-INF/views/errorMessage.jsp" %>

        <spring:url value="" var="emptyUrl"/>
        <form name="form" novalidate action="${ fn:escapeXml(emptyUrl) }" method="post">
            <table class="dataTable">
                <tbody>
                    <tr>
                        <td>User</td>
                        <td class="inputValue">
                            <c:out value="${ user.name }"></c:out>
                        </td>
                    </tr>
                    <tr>
                        <td>Current Password</td>
                        <td class="inputValue">
                            <input focus-on="focusInput" type='password' id="currentPasswordInput" name='currentPassword' ng-model="user.currentPassword" size="30" required/>
                            <span id="passwordRequiredError" class="errors" ng-show="form.currentPassword.$dirty && form.currentPassword.$error.required">Password is required.</span>
                            <c:if test="${ not empty currentPassword }">
                                <span id="currentPasswordMismatchError" class="errors"> <c:out value="${ currentPassword }"/></span>
                            </c:if>
                        </td>
                    </tr>
                    <tr>
                        <td>New Password</td>
                        <td class="inputValue">
                            <input password-validate="{{ user.passwordConfirm }}" ng-model="user.unencryptedPassword" required type="password" id="passwordInput" name="unencryptedPassword" size="30"/>
                            <span id="charactersRequiredError" class="errors" ng-show="lengthRemaining">{{ lengthRemaining }} characters needed</span>
                            <span id="passwordMatchError" class="errors" ng-show="form.unencryptedPassword.$dirty && form.unencryptedPassword.$error.matches">Passwords do not match.</span>
                            <c:if test="${ not empty password }">
                                <span class="errors"> <c:out value="${ password }"/></span>
                            </c:if>
                        </td>
                    </tr>
                    <tr>
                        <td>Confirm New Password</td>
                        <td class="inputValue">
                            <input ng-model="user.passwordConfirm" required type="password" style="margin-bottom:0px" id="passwordConfirmInput" name="passwordConfirm" size="30" />
                            <span id="confirmRequiredError" class="errors" ng-show="form.passwordConfirm.$dirty && form.passwordConfirm.$error.required">This field is required.</span>
                        </td>
                    </tr>
                </tbody>
            </table>
            <input ng-disabled="form.$invalid" style="margin-top:15px" class="btn btn-primary" id="updateUserButton" type="submit" value="Update Password" />
        </form>
    </div>
</body>
