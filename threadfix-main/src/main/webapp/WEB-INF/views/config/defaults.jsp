<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Configure Defaults</title>
</head>

<body id="config">
	<h2>Configure Defaults</h2>
	
	<%@ include file="/WEB-INF/views/successMessage.jspf" %>
	
	<spring:url value="" var="emptyUrl"></spring:url>
	<form:form modelAttribute="defaultConfiguration" name="formEditUser" action="${ fn:escapeXml(emptyUrl) }">
		<table class="dataTable">
			<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_ROLES">
			<tr>
				<td>Global Group enabled for new users?</td>
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
			</security:authorize>
			<c:if test="${ ldap_plugin }">
			<tr>
				<td class="no-color">LDAP Search Base</td>
				<td class="no-color">
					<form:input id="activeDirectoryBase" path="activeDirectoryBase" cssClass="focus" size="60" maxlength="255" value="${user.name}"/>
				</td>
				<td class="no-color" style="padding-left: 5px">
					<form:errors path="activeDirectoryBase" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td class="no-color">LDAP User DN</td>
				<td class="no-color">
					<form:input id="activeDirectoryUsername" path="activeDirectoryUsername" cssClass="focus" size="60" maxlength="255" value="${user.name}"/>
				</td>
				<td class="no-color" style="padding-left: 5px">
					<form:errors path="activeDirectoryUsername" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td class="no-color">LDAP Password</td>
				<td class="no-color">
					<form:input id="activeDirectoryCredentials" path="activeDirectoryCredentials" cssClass="focus" size="60" maxlength="255" value="${user.name}"/>
				</td>
				<td class="no-color" style="padding-left: 5px">
					<form:errors path="activeDirectoryCredentials" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td class="no-color">LDAP URL</td>
				<td class="no-color">
					<form:input id="activeDirectoryURL" path="activeDirectoryURL" cssClass="focus" size="60" maxlength="255" value="${user.name}"/>
				</td>
				<td class="no-color" style="padding-left: 5px">
					<form:errors path="activeDirectoryURL" cssClass="errors" />
				</td>
			</tr>
			</c:if>
		</table>
		<br/>
		<button class="btn btn-primary" type="submit" id="updateDefaultsButton">Update Defaults</button>
	</form:form>
</body>
