<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Scanner Plugin</title>
</head>

<body id="wafs">
	<h2>Scanner Plugin Management</h2>
	
	<%@ include file="/WEB-INF/views/successMessage.jspf" %>
	<%@ include file="/WEB-INF/views/errorMessage.jsp"%>
	
	<c:if test="${ not empty pluginCheckBean.lastImportDate }">
		Vulnerability Mappings were last updated from the 
		<fmt:formatDate value="${ pluginCheckBean.lastImportDate.time }" type="both" dateStyle="short" timeStyle="short" />
		scanner plugin.
	</c:if>
	<c:if test="${ empty pluginCheckBean.lastImportDate }">
		Vulnerability Mappings have never been updated.
	</c:if>
	
	<c:if test="${ not empty pluginCheckBean.currentPluginDate }">
		The current scanner plugin is dated 
		<fmt:formatDate value="${ pluginCheckBean.currentPluginDate.time }" type="both" dateStyle="short" timeStyle="short" />.
	</c:if>
	
	<c:if test="${ not pluginCheckBean.canUpdate }">
		No update is necessary.
	</c:if>
	
	<c:if test="${ pluginCheckBean.canUpdate }">
		<br>
		<br>
		<c:url value="/scanplugin/updateChannelVuln" var="updateUrl"/>
		<a href="${ fn:escapeXml(updateUrl) }" class="btn btn-primary">Update Mappings</a>
	</c:if>

	<c:if test="${ not empty resultList }">
		<table class="table table-striped">
			<thead>
				<tr>
					<th class="long first">Channel Type</th>
					<th class="centered">Vulnerabilites updated</th>
                    <th class="centered last">Severities updated</th>
				</tr>
			</thead>
			<tbody id="wafTableBody">
			<c:if test="${ empty resultList }">
				<tr class="bodyRow">
					<td colspan="5" style="text-align:center;">No Channel Types updated.</td>
				</tr>
			</c:if>
			<c:forEach var="result" items="${ resultList }" varStatus="status">
				<tr class="bodyRow">
					<td class="details" id="name${ status.count }">
						<c:out value="${ result[0] }"/>
					</td>
					<td class="centered" id="vulnsUpdated${ status.count }">
						<c:out value="${ result[1] }"/>
					</td>
                    <td class="centered last" id="sevsUpdated${ status.count }">
                        <c:out value="${ result[2] }"/>
                    </td>
				</tr>
			</c:forEach>
			</tbody>
		</table>
	</c:if>
</body>
