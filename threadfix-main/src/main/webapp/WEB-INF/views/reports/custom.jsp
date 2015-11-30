<div class="vuln-search-filter-control" style="width:900px;min-height: 500px">
	<div class="btn-group" style="height: auto">
		<button ng-hide="loading" id="actionItems" class="btn dropdown-toggle" data-toggle="dropdown" type="button">
			Choose Report <span class="caret"></span>
		</button>
		<ul class="dropdown-menu">
			<c:forEach items="${customReports}" var="report">
				<li ng-init="customReportId = ${report.id}" ng-click="reportId = ${report.id}; selectCustomReport(customReportId)">
					<a ng-non-bindable class="pointer"><c:out value="${report.displayName}"/></a>
				</li>
			</c:forEach>
		</ul>

		<button id="submittingButton" ng-disabled class="btn" ng-show="loading">
			<span class="spinner dark"></span>
			Loading
		</button>
	</div>

	<%@ include file="/WEB-INF/views/angular-init.jspf"%>
	<div>
		<c:forEach items="${customReports}" var="report">
			<div ng-show="selectedReport == ${report.id}">
				<jsp:include page="${ report.jspFilePath }"/>
			</div>
		</c:forEach>
	</div>
</div>


