<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Remote Providers</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-providers-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-provider-modal-controller.js"></script>
</head>

<spring:url value="" var="emptyUrl"/>
<body ng-controller="RemoteProvidersController" ng-init="csrfToken = '<c:out value="${ emptyUrl }"/>'">
	<h2>Remote Providers</h2>

    <%@ include file="/WEB-INF/views/config/remoteproviders/configure.jsp" %>

    <div id="helpText">
		Remote Providers are links to services which
		import vulnerability data into ThreadFix.
	</div>

    <div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <div ng-show="initialized" id="headerDiv">
		<table class="table table-striped">
            <thead>
            <tr>
                <th class="medium first">Name</th>
                <th class="medium">User name</th>
                <c:if test="${ not canManageRemoteProviders }">
                    <th class="medium last">API Key</th>
                </c:if>
                <c:if test="${ canManageRemoteProviders }">
                    <th class="medium">API Key</th>
                    <th class="medium last">Configure</th>
                </c:if>
            </tr>
            </thead>
            <tbody id="remoteProvidersTableBody">
                <tr ng-show="providers.length === 0" class="bodyRow">
                    <td colspan="4" style="text-align:center;"> No providers found.</td>
                </tr>
                <tr ng-repeat="provider in providers" class="bodyRow">
                    <td id="name{{ $index }}">
                        {{ provider.name }}
                    </td>
                    <td id="username{{ $index }}">
                        {{ provider.username }}
                    </td>
                    <td id="apiKey{{ $index }}">
                        {{ provider.apiKey }}
                    </td>
                    <c:if test="${ canManageRemoteProviders }">
                        <td>
                            <a id="configure{{ $index }}" class="btn" ng-click="configure(provider)">Configure</a>
                        </td>
                    </c:if>
                </tr>
            </tbody>
        </table>

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
