<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Password Change</title>
</head>

<body id="config">
	<h2>User Password Change</h2>
	
	<c:if test="${ not empty successMessage }">
		<div class="alert alert-success">
			<button class="close" data-dismiss="alert" type="button">×</button>
			<c:out value="${ successMessage }"/>
		</div>
	</c:if>
	
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
					<form:password style="margin-bottom:0px" id="currentPasswordInput" path="currentPassword" cssClass="focus" size="30"/>
				</td>
				<td style="padding-left: 5px">
					<form:errors path="currentPassword" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td>New Password</td>
				<td class="inputValue">
					<form:password style="margin-bottom:0px" id="passwordInput" path="unencryptedPassword" size="30"/>
				</td>
				<td style="padding-left: 5px">
					<form:errors path="password" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td>Confirm New Password</td>
				<td class="inputValue">
					<form:password style="margin-bottom:0px" id="passwordConfirmInput" path="passwordConfirm" size="30"/>
				</td>
			</tr>
		</table>

		<input style="margin-top:15px" class="btn btn-primary" id="updateUserButton" type="submit" value="Update Password" />
		
	</form:form>
</body>
