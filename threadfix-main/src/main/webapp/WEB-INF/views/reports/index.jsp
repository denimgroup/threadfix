<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Reports</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/report_page.js"></script>
</head>

<body id="reports">
	
	<%@ include file="/WEB-INF/views/errorMessage.jsp" %>
	<spring:url value="/reports/ajax" var="emptyUrl"></spring:url>	
	
	<div class="alert alert-danger" style="display:none" id="connectionUnavailableMessage">
		<button class="close" data-dismiss="alert" type="button">×</button>
		ThreadFix was unable to connect to the server. Ensure that it is available and try again.
	</div>

	<h2>Reports</h2>
	
	<c:if test="${ not empty error }">
		<div class="row-fluid">
			<div class="span12">
				<div class="alert">
					<button class="close" data-dismiss="alert" type="button">×</button>
					<c:out value="${ error }"/>
				</div>
			</div>
		</div>
	</c:if>
	<ul class="nav nav-tabs margin-top">
		<li class="active pointer">
			<a data-toggle="tab" id="trendingTabLink" class="reportTypeListSelector" data-report-list="trendingReportSelect">
				Trending
			</a>
		</li>
		<li class="pointer">
			<a data-toggle="tab" id="snapshotTabLink" class="reportTypeListSelector" data-report-list="snapshotReportSelect">
				Snapshot
			</a>
		</li>
		<li class="pointer">
			<a data-toggle="tab" id="comparisonTabLink" class="reportTypeListSelector" data-report-list="comparisonReportSelect">
				Comparison
			</a>
		</li>
	</ul>
		
	<form:form style="padding-bottom:15px" id="reportForm" modelAttribute="reportParameters" action="${ fn:escapeXml(emptyUrl) }">
		<span id="formDiv">
			<select class="reportTypeSelect" id="trendingReportSelect" data-tab="trendingTabLink">
				<option data-report-id="1" data-url="<c:out value="${ emptyUrl }"/>"
					<c:if test="${ hasVulnerabilities }">
						selected="selected"
					</c:if>
				>
					Trending Scans
				</option>
				<option data-report-id="7" data-url="<c:out value="${ emptyUrl }"/>">
					Monthly Progress
				</option>
				<option data-report-id="9" data-url="<c:out value="${ emptyUrl }"/>">
					12 Month Vulnerability Burndown
				</option>
				<option data-report-id="10" data-url="<c:out value="${ emptyUrl }"/>">
					Top 20 Vulnerable Applications
				</option>
			</select>
			
			<c:if test="${ hasVulnerabilities }">
				<select class="reportTypeSelect" id="snapshotReportSelect" data-tab="snapshotTabLink">
					<option data-report-id="2" data-url="<c:out value="${ emptyUrl }"/>">
						Point in Time
					</option>
					<option data-report-id="3" data-url="<c:out value="${ emptyUrl }"/>">
						Progress By Vulnerability
					</option>
					<option data-report-id="8" data-url="<c:out value="${ emptyUrl }"/>">
						Portfolio Report
					</option>
					<option data-report-id="11" data-url="<c:out value="${ emptyUrl }"/>">
						Vulnerability List
					</option>
				</select>
				
				<select class="reportTypeSelect" id="comparisonReportSelect" data-tab="comparisonTabLink">
					<option data-report-id="4" data-url="<c:out value="${ emptyUrl }"/>">
						Comparison By Vulnerability
					</option>
					<option data-report-id="5" data-url="<c:out value="${ emptyUrl }"/>">
						Comparison Summary
					</option>
					<option data-report-id="6" data-url="<c:out value="${ emptyUrl }"/>">
						Comparison Detail
					</option>
				</select>
			</c:if>
		</span>
		
		Team
		<span id="orgDropDown">
			<form:select style="margin-bottom:0px;width:160px;" path="organizationId"
					id="orgSelect" class="selectFiller" data-select-target="appSelect"
					data-refresh-url="${ emptyUrl }">
				<c:set var="optionsBase" value="[{\"id\":\"-1\", \"name\":\"All\"}"/>
				<option value="-1" data-select-items="<c:out value="${ optionsBase }"/>]">All</option>
				<c:forEach var="organization" items="${ organizationList }">
					<c:if test="${ organization.active }">
						<c:set var="options" value="${ optionsBase }"/>
						<c:set var="quote" value="\""/>
						<c:forEach var="application" items="${ organization.activeApplications}">
							<c:set var="options" value="${options},{${ quote }id${ quote }:${ quote }${ application.id }${ quote }, ${ quote }name${ quote }:${ quote }${ application.name }${ quote }}"/>
						</c:forEach>
						<option value="${ organization.id }" 
							<c:if test="${ not empty firstTeamId and firstTeamId == organization.id }">
								selected="selected"								
							</c:if>
						data-select-items="<c:out value="${ options }"/>]">
							<c:out value="${ organization.name }" />
						</option>
					</c:if>
				</c:forEach>
			</form:select>
		</span>
	
		Application
		<span id="appDropDown">
			<form:select style="margin-bottom:0px;width:160px;" path="applicationId"
					id="appSelect" data-first-app-id="${ firstAppId }">
				<option value="-1">All</option>
			</form:select>
			<form:errors path="applicationId" />
		
	
			<spring:url value="/reports/ajax/export" var="exportUrl"></spring:url>	
			<spring:url value="/reports/ajax" var="emptyUrl"></spring:url>	
	
			<a id="csvLink" 
					class="reportDownload btn btn-primary" style="display:none"
					data-url="<c:out value="${ exportUrl }"/>"
					data-format-id="2">
				Export CSV
			</a>
		
			<a id="pdfLink" 
					class="reportDownload btn btn-primary" style="display:none"
					data-url="<c:out value="${ exportUrl }"/>"
					data-format-id="3">
				Export PDF
			</a>
		</span>
		
	</form:form>
		
	<div id="successDiv" 
			<c:if test="${ not hasVulnerabilities or empty organizationList }">
				data-hide-reports="1" 
			</c:if>
			data-first-report="<c:out value="${ firstReport }"/>">
		<c:if test="${ not hasVulnerabilities }">
			<div class="alert alert-danger" style="margin-top:10px">
				<button class="close" data-dismiss="alert" type="button">×</button>
				<strong>No Vulnerabilities found.</strong> Upload a scan and try again.
				<spring:url value="/organizations" var="teamsPageUrl"/>
				<a href="${ teamsPageUrl }">Get Started</a>
			</div>
		</c:if>
	</div>
		
</body>
