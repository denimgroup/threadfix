<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:if test="${ user['new'] }">New </c:if>User</title>
	<script>
		function confirmRoles() {
			return $("#roleSelect").children("option").filter(":selected").text() !== "User" || 
				confirm("You are switching roles from Administrator to User and will be logged out after this change.");
		}
	</script>
</head>

<body id="config">
	<h2><c:if test="${ user['new'] }">New </c:if>User</h2>
	
	<spring:url value="" var="emptyUrl"></spring:url>
	<form:form modelAttribute="user" name="formEditUser" action="${ fn:escapeXml(emptyUrl) }">
		<table class="dataTable">
			<tr>
				<td class="label">Name:</td>
				<td class="inputValue">
					<form:input id="nameInput" path="name" cssClass="focus" size="30" maxlength="25" />
				</td>
				<td style="padding-left: 5px">
					<form:errors path="name" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td class="label">Password:</td>
				<td class="inputValue">
					<form:password id="passwordInput" path="unencryptedPassword" />
				</td>
				<td style="padding-left: 5px">
					<form:errors path="password" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td class="label">Confirm:</td>
				<td class="inputValue">
					<form:password id="passwordConfirmInput" path="passwordConfirm" />
				</td>
			</tr>
		</table>
		<br/>
		
		<c:choose>
			<c:when test="${ user['new'] }">
				<input id="addUserButton" type="submit" value="Add User" />
				<span style="padding-left: 10px">
					<a id="cancelLink" href="<spring:url value="/configuration/users" />">Back to Users Index</a>
				</span>
			</c:when>
			<c:otherwise>
				<input id="updateUserButton" type="submit" value="Update User" />
				<span style="padding-left: 10px">
					<spring:url value="/configuration/users" var="userUrl">
						<spring:param name="userId" value="${ user.id }"/>
					</spring:url>
					<a id="cancelLink" href="${ fn:escapeXml(userUrl) }">Back to Users Index</a>
				</span>
			</c:otherwise>
		</c:choose>
		
	</form:form>
</body>
