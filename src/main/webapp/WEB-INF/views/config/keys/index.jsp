<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>API Keys</title>
</head>

<body>
	<h2>API Keys</h2>
	
	<div id="helpText">
		ThreadFix API Keys are used to access the REST interface.<br/>
	</div>
	
	<table class="formattedTable">
		<thead>
			<tr>
				<th class="medium first">Key</th>
				<th class="short">Note</th>
				<th class="short">Edit</th>
				<th class="short">Delete</th>
				<c:if test="${ not empty apiKeyList }">
					<security:authorize ifAnyGranted="ROLE_ADMIN">
						<th class="short last">Restricted</th>
					</security:authorize>
				</c:if>
			</tr>
		</thead>
		<tbody>
			<c:if test="${ empty apiKeyList }">
				<tr class="bodyRow">
					<td colspan="4" style="text-align:center;">No keys found.</td>
				</tr>
			</c:if>
			<c:forEach var="key" items="${ apiKeyList }">
				<tr class="bodyRow">
					<td>
						<c:out value="${ key.apiKey }"></c:out>
					</td>
					<td>
						<c:out value="${ key.note }"></c:out>
					</td>
					<td>
						<spring:url value="/configuration/keys/{keyId}/edit" var="keyEditUrl">
							<spring:param name="keyId" value="${ key.id }" />
						</spring:url>
						<a href="${ fn:escapeXml(keyEditUrl) }">Edit</a> 
					</td>
					<td>
						<spring:url value="/configuration/keys/{keyId}/delete" var="keyDeleteUrl">
							<spring:param name="keyId" value="${ key.id }" />
						</spring:url>
						<form:form method="POST" action="${ fn:escapeXml(keyDeleteUrl) }">
							<input type="submit" onclick="return confirm('Are you sure you want to delete this API Key?')" value="Delete"/>
						</form:form>
					</td>
					<security:authorize ifAnyGranted="ROLE_ADMIN">
						<td>
							<c:out value="${ key.isRestrictedKey }"/>
						</td>
					</security:authorize>
				</tr>
			</c:forEach>
			<tr class="footer">
				<td colspan="4" class="first">
					<a href="<spring:url value="/configuration/keys/new" />">Create New Key</a>
				</td>
				<td colspan="3" class="last pagination" style="text-align:right"></td>
			</tr>
		</tbody>
	</table>
	<br/>
</body>
