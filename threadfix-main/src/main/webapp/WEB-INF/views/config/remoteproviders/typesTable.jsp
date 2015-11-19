<%@ include file="/common/taglibs.jsp"%>

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
	<c:if test="${ empty remoteProviders }">
		<tr class="bodyRow">
			<td colspan="4" style="text-align:center;"> No providers found.</td>
		</tr>
	</c:if>
	<c:forEach var="remoteProviderType" items="${ remoteProviders }" varStatus="status">
		<tr class="bodyRow">
			<td ng-non-bindable id="name${status.count }">
				<c:out value="${ remoteProviderType.name }" />
			</td>
			<td ng-non-bindable id="username${status.count }">
				<c:if test="${ not empty remoteProviderType.username }">
					<c:out value="${ remoteProviderType.username }" />
				</c:if>
			</td>
			<td ng-non-bindable id="apiKey${status.count }">
				<c:if test="${ not empty remoteProviderType.apiKey }">
					<c:out value="${ remoteProviderType.apiKey }" />
				</c:if>
			</td>
			<c:if test="${ canManageRemoteProviders }">
			<td>
				<a id="configure${status.count }" href="#remoteProviderEditModal${ remoteProviderType.id }" role="button" class="btn" data-toggle="modal">Configure</a>
				<div id="remoteProviderEditModal${ remoteProviderType.id }" class="modal hide fade" tabindex="-1"
						role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
					<%@ include file="/WEB-INF/views/config/remoteproviders/configure.jsp" %>
				</div>
			</td>
			</c:if>
		</tr>
	</c:forEach>
	</tbody>
</table>
