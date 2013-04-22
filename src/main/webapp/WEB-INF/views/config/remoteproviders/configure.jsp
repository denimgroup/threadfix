<%@ include file="/common/taglibs.jsp"%>

<div class="modal-header">
	<h4 id="myModalLabel">Configure <c:out value="${ remoteProviderType.name }"/></h4>
</div>
<spring:url value="/configuration/remoteproviders/{typeId}/configure" var="saveUrl">
	<spring:param name="typeId" value="${ remoteProviderType.id }"/>
</spring:url>
<form:form id="remoteProviderEditForm${ remoteProviderType.id }" modelAttribute="remoteProviderType" method="post" autocomplete="off" action="${ fn:escapeXml( saveUrl ) }">
<div class="modal-body">
	<%@ include file="/WEB-INF/views/errorMessage.jsp"%>
	<table class="dataTable">
		<tbody>
			<c:if test="${remoteProviderType.hasUserNamePassword }">
				<tr>
					<td class="no-color">Username</td>
					<td class="no-color inputValue">
						<c:if test="${ not empty remoteProviderType.username }">
							<script>
								initialUsername = '<c:out value="${ remoteProviderType.username }"/>';
							</script>
						</c:if>
						<form:input id="usernameInput" path="username" size="50" maxlength="60" style="width:420px" />
					</td>
					<td class="no-color" style="padding-left:5px">
						<form:errors path="username" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td class="no-color">Password</td>
					<td class="no-color inputValue">
						<form:input id="passwordInput" type="password" path="password" size="50" maxlength="60" style="width:420px" />
					</td>
					<td class="no-color" style="padding-left:5px">
						<form:errors path="password" cssClass="errors" />
					</td>
				</tr>
			</c:if>
			<c:if test="${remoteProviderType.hasApiKey}">
				<tr>
					<td class="no-color">API Key</td>
					<td class="no-color inputValue">
						<c:if test="${ not empty remoteProviderType.apiKey }">
							<script>
								initialApiKey = '<c:out value="${ remoteProviderType.apiKey }"/>';
							</script>
						</c:if>
						<form:input id="apiKeyInput" path="apiKey" size="50" maxlength="60" style="width:420px" />
					</td>
					<td class="no-color" style="padding-left:5px">
						<form:errors path="apiKey" cssClass="errors" />
					</td>
				</tr>
			</c:if>
			<c:if test="${ remoteProviderType.isQualys }">
				<tr>
					<td class="no-color">Region:</td>
					<td class="no-color inputValue">
						<form:radiobutton path="isEuropean" value="false"/> US 
						<form:radiobutton path="isEuropean" value="true"/> EU
					</td>
				</tr>
			</c:if>
		</tbody>
	</table>
	<%-- <c:if test="${remoteProviderType.hasUserNamePassword }">
		<button style="margin-top:10px;" id="submitButton" class="btn btn-primary" type="submit" onclick="if (initialUsername && initialUsername !== $('#usernameInput').val()) { return confirm('Warning: You have changed your username, all existing ${ remoteProviderType.name } apps will be deleted.') }">Save</button>
	</c:if>
	
	<c:if test="${not remoteProviderType.hasUserNamePassword }">
		<button style="margin-top:10px;" id="submitButton" class="btn btn-primary" type="submit" onclick="if (initialApiKey && initialApiKey !== $('#apiKeyInput').val()) { return confirm('Warning: You have changed your API key, all existing ${ remoteProviderType.name } apps will be deleted.') }">Save</button>
	</c:if>
	
	<span style="padding-left:10px"><a id="backToIndexLink" href="<spring:url value="/configuration/remoteproviders" htmlEscape="true"/>">Back to Index</a></span>
 --%></div>
<div class="modal-footer">
	<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
	<a id="submitRemoteProviderFormButton${ remoteProviderType.id }" class="modalSubmit btn btn-primary" 
			data-success-div="headerDiv">Save Changes</a>
</div>
	
</form:form>
