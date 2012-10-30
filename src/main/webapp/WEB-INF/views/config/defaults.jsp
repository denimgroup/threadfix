<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Configure Defaults</title>
</head>

<body id="config">
	<h2>Configure Defaults</h2>
	
	<spring:url value="" var="emptyUrl"></spring:url>
	<form:form modelAttribute="model" name="formEditUser" action="${ fn:escapeXml(emptyUrl) }">
		<table class="dataTable">
			<tr>
				<td class="label">Global Group enabled for new users?</td>
				<td class="inputValue" style="text-align: left;">
					<form:checkbox id="globalGroupEnabledCheckbox" path="globalGroupEnabled" />
				</td>
				<td class="inputValue">
					<form:select id="roleSelect" path="defaultRoleId">
						<form:option value="0" label="Select a role" />
						<form:options items="${ roleList }" itemValue="id" itemLabel="displayName" />
					</form:select>
				</td>
				<td style="border: 0px solid black; background-color: white; padding-left: 5px">
					<form:errors id="globalGroupEnabledErrors" path="globalGroupEnabled" cssClass="errors" />
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
