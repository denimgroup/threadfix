<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Password Change</title>
</head>

<body id="config">
	<h2>User Password Change</h2>
	
	<spring:url value="" var="emptyUrl"></spring:url>
	<form:form modelAttribute="user" name="formEditUser" action="${ fn:escapeXml(emptyUrl) }">
		<table class="dataTable">
			<tr>
				<td>User</td>
				<td class="inputValue">
					<c:out value="${ user.name }"/>
				</td>
			</tr>
			<tr>
				<td>Current Password</td>
				<td class="inputValue">
					<form:password id="currentPasswordInput" path="currentPassword" cssClass="focus" size="30"/>
				</td>
				<td style="padding-left: 5px">
					<form:errors path="currentPassword" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td>New Password</td>
				<td class="inputValue">
					<form:password id="passwordInput" path="unencryptedPassword" size="30"/>
				</td>
				<td style="padding-left: 5px">
					<form:errors path="password" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td>Confirm New Password</td>
				<td class="inputValue">
					<form:password id="passwordConfirmInput" path="passwordConfirm" size="30"/>
				</td>
			</tr>
		</table>
		<br/>

		<input id="updateUserButton" type="submit" value="Update Password" />
		<span style="padding-left: 10px">
			<spring:url value="/configuration" var="userUrl"/>
			<a id="cancelLink" href="${ fn:escapeXml(userUrl) }">Back to Configuration Index</a>
		</span>
		
	</form:form>
</body>
