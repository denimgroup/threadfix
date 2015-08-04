<%@ include file="/common/taglibs.jsp"%>

<div id="scannerMappings" ng-controller="MappingsPageController">
	<h2>Scanner To CWE Mappings</h2>

	<%@ include file="/WEB-INF/views/angular-init.jspf"%>

	<%@ include file="../scans/createMappingModal.jsp" %>

	<%@ include file="/WEB-INF/views/successMessage.jspf" %>
	<%@ include file="/WEB-INF/views/errorMessage.jspf"%>

	<c:if test="${ not empty pluginCheckBean.currentPluginDate }">
		<div>
			The current scanner plugin is dated
			<fmt:formatDate value="${ pluginCheckBean.currentPluginDate.time }" type="both" dateStyle="short" timeStyle="short" />.
		</div>
	</c:if>

	<c:if test="${ not empty exportText }">
		<div>
			<h4 style="padding-top:8px">Mappings Export</h4>
			<a class="btn" href="mailto:support@threadfix.org?subject=Mappings-Update&body=<c:out value="${ fn:escapeXml(exportText) }"/>" target="_top">
				Export New Mappings to Denim Group (Through Email)
			</a>
		</div>
	</c:if>

	<div ng-controller="ScanUnmappedFindingTableController">
		<h4 style="padding-top:30px">Unmapped Types</h4>
		<%@ include file="/WEB-INF/views/successMessage.jspf" %>
		<div id="unmappedTable" ng-if="numFindings && numFindings > 0">
			<%@ include file="../scans/unmappedTable.jsp" %>
		</div>
		<div id="allFindingsHaveMappings" ng-if="!numFindings || numFindings == 0">
			All Findings have vulnerability mappings.
		</div>
	</div>

</div>
