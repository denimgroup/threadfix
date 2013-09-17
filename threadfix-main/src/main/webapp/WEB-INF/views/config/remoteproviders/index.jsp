<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Remote Providers</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote_providers_page.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
</head>

<body>
	<form:form modelAttribute="error" name="formErrors">
		<form:errors cssClass="errors" />
	</form:form>

	<h2>Remote Providers</h2>

	<c:if test="${ not empty successMessage }">
		<div class="alert alert-success">
			<button class="close" data-dismiss="alert" type="button">×</button>
			<c:out value="${ successMessage }"/>
		</div>
	</c:if>
	
	<%@ include file="/WEB-INF/views/errorMessage.jsp"%>
	
	<div id="helpText">
		Remote Providers are links to services which
		import vulnerability data into ThreadFix.
	</div>
	
	<div id="headerDiv">
		<%@ include file="/WEB-INF/views/config/remoteproviders/typesTable.jsp" %>
	</div>
	
	<c:set var="appsPresent" value="false"/>
	
	<c:forEach var="remoteProvider" items="${ remoteProviders }" varStatus="outerStatus">
		<div id="toReplace${ remoteProvider.id }">
			<spring:url value="/login.jsp" var="loginUrl"/>
			<spring:url value="/configuration/remoteproviders/{id}/table" var="tableUrl">
				<spring:param name="id" value="${ remoteProvider.id }"/>
			</spring:url>
			<script>refillElement('#toReplace${ remoteProvider.id }', '${tableUrl}', 1, '<c:out value="${ loginUrl }"/>');</script>
			<%@ include file="/WEB-INF/views/config/remoteproviders/rpAppTable.jsp" %>
		</div>
	</c:forEach>
</body>
