<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Remote Providers</title>
</head>

<body id="config">
	<form:form modelAttribute="error" name="formErrors">
		<form:errors cssClass="errors" />
	</form:form>

	<h2>Remote Provider <c:out value="${ remoteProviderType.name }"/></h2>
	
	<div id="helpText">
		Remote Providers are links to services which
		import vulnerability data into ThreadFix.
	</div>

	<!-- TODO make this smarter by only showing relevant fields -->
	<spring:url value="" var="emptyUrl"/>
	<form:form modelAttribute="remoteProviderType" method="post" autocomplete="off" action="${ fn:escapeXml( emptyUrl) }">
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Username:</td>
				<td class="inputValue">
					<form:input id="usernameInput" path="username" size="50" maxlength="60" />
				</td>
				<td style="padding-left:5px">
					<form:errors path="username" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td class="label">Password:</td>
				<td class="inputValue">
					<form:input id="passwordInput" type="password" path="password" size="50" maxlength="60" />
				</td>
				<td style="padding-left:5px">
					<form:errors path="password" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td class="label">API Key:</td>
				<td class="inputValue">
					<form:input id="apiKeyInput" path="apiKeyString" size="50" maxlength="60" />
				</td>
				<td style="padding-left:5px">
					<form:errors path="apiKeyString" cssClass="errors" />
				</td>
			</tr>
		</tbody>
	</table>
	
	<input style="margin-top:10px;" id="submitButton" type="submit" value="Save" onclick="return confirm('If you have changed your username or API key, all existing apps will be deleted.')" />
	<span style="padding-left: 10px"><a href="<spring:url value="configuration/remoteproviders" htmlEscape="true"/>">Back to Index</a></span>
		
	</form:form>
	
</body>