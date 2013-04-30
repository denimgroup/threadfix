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
	
	<c:if test="${ empty organizationList }">
		No Teams with Applications were found. Please add one and try again.
	</c:if>

	<c:if test="${ not empty organizationList }">
		<div class="container-fluid" style="margin-left:-100px">
			<div class="row-fluid">
				<div class="span4">
					<h2>Reports</h2>
				</div>
			</div>				
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
			
			
			<div class="row-fluid">
	
				<div class="span3" style="float:left" id="formDiv">
				
					<div id="helpText">This page is used to generate various reports.
					<br/>Please note that the Portfolio Report does not filter on a Team / Application basis and is only available in the HTML format.</div>
					
					<table class="table">
						<tr class="reportFilterHeader">
							<th colspan="2">Trending Reports</th>
						</tr>
						<tr class="sidebar sidebar1
								<c:if test="${ hasVulnerabilities }">
										sidebar-active
								</c:if>
								" data-report-id="1" data-url="<c:out value="${ emptyUrl }"/>">
							<td><a>Trending Scans</a></td>
							<td><div class="sidebar-arrow
									<c:if test="${ hasVulnerabilities }">
											sidebar-active
									</c:if>
									" id="arrow1">&gt;</div></td>
						</tr>
						<tr class="sidebar sidebar7" data-report-id="7" data-url="<c:out value="${ emptyUrl }"/>">
							<td><a>Monthly Progress</a></td>
							<td><div class="sidebar-arrow" id="arrow7">&gt;</div></td>
						</tr>
						<tr class="sidebar sidebar9" data-report-id="9" data-url="<c:out value="${ emptyUrl }"/>">
							<td><a>Vulnerability Burndown</a></td>
							<td><div class="sidebar-arrow" id="arrow9">&gt;</div></td>
						</tr>
						<tr class="sidebar sidebar10" data-report-id="10" data-url="<c:out value="${ emptyUrl }"/>">
							<td><a>Top 20 Vulnerable Applications</a></td>
							<td><div class="sidebar-arrow" id="arrow10">&gt;</div></td>
						</tr>
						
						<tr class="reportFilterHeader">
							<th colspan="2">Progress Reports</th>
						</tr>
						<tr class="sidebar sidebar2" data-report-id="2" data-url="<c:out value="${ emptyUrl }"/>">
							<td><a>Point in Time</a></td>
							<td><div class="sidebar-arrow" id="arrow2">&gt;</div></td>
						</tr>
						<tr class="sidebar sidebar3" data-report-id="3" data-url="<c:out value="${ emptyUrl }"/>">
							<td><a>Progress By Vulnerability</a></td>
							<td><div class="sidebar-arrow" id="arrow3">&gt;</div></td>
						</tr>
						<tr class="sidebar sidebar8" data-report-id="8" data-url="<c:out value="${ emptyUrl }"/>">
							<td><a>Portfolio Report</a></td>
							<td><div class="sidebar-arrow" id="arrow8">&gt;</div></td>
						</tr>
						
						<tr class="reportFilterHeader">
							<th colspan="2">Scanner Comparison Reports</th>
						</tr>
						<tr class="sidebar sidebar4" data-report-id="4" data-url="<c:out value="${ emptyUrl }"/>">
							<td><a>Comparison By Vulnerability</a></td>
							<td><div class="sidebar-arrow"id="arrow4">&gt;</div></td>
						</tr>
						<tr class="sidebar sidebar5" data-report-id="5" data-url="<c:out value="${ emptyUrl }"/>">
							<td><a>Comparison Summary</a></td>
							<td><div class="sidebar-arrow" id="arrow5">&gt;</div></td>
						</tr>
						<tr class="sidebar sidebar6" data-report-id="6" data-url="<c:out value="${ emptyUrl }"/>">
							<td ><a>Comparison Detail</a></td>
							<td><div class="sidebar-arrow" id="arrow6">&gt;</div></td></tr>
					</table>
					
				</div>
				<div class="span9">
					<div class="row-fluid">
						<div class="span12">
							<form:form id="reportForm" modelAttribute="reportParameters" action="${ fn:escapeXml(emptyUrl) }">
								Team
								<span id="orgDropDown">
									<form:select style="margin-bottom:0px;width:160px;" path="organizationId"
											id="orgSelect" class="selectFiller" data-select-target="appSelect"
											data-refresh-url="${ emptyUrl }">
										<c:set var="optionsBase" value="[{\"id\":\"-1\", \"name\":\"All\"}"/>
										<option value="-1">All</option>
										<c:forEach var="organization" items="${ organizationList }">
											<c:if test="${ organization.active }">
												<c:set var="options" value="${ optionsBase }"/>
												<c:set var="quote" value="\""/>
												<c:forEach var="application" items="${ organization.activeApplications}">
													<c:set var="options" value="${options},{${ quote }id${ quote }:${ quote }${ application.id }${ quote }, ${ quote }name${ quote }:${ quote }${ application.name }${ quote }}"/>
												</c:forEach>
												<option value="${ organization.id }" data-select-items="<c:out value="${ options }"/>]">
													<c:out value="${ organization.name }" />
												</option>
											</c:if>
										</c:forEach>
									</form:select>
								</span>
							
								Application
								<span id="appDropDown">
									<form:select style="margin-bottom:0px;width:160px;" path="applicationId"
											id="appSelect">
										<option value="-1">All</option>
									</form:select>
									<form:errors path="applicationId" />
								
							
									<spring:url value="/reports/ajax/export" var="exportUrl"></spring:url>	
									<spring:url value="/reports/ajax" var="emptyUrl"></spring:url>	
							
									<a id="csvLink" class="reportDownload btn btn-primary" style="display:none"
											data-url="<c:out value="${ exportUrl }"/>"
											data-format-id="2">
										Export CSV
									</a>
								
									<a id="pdfLink" class="reportDownload btn btn-primary" style="display:none"
											data-url="<c:out value="${ exportUrl }"/>"
											data-format-id="3">
										Export PDF
									</a>
								</span>
							</form:form>
						</div>
					</div>
					
					<div class="row-fluid">
						<div class="span12" id="successDiv" 
								<c:if test="${ not hasVulnerabilities }">
									data-hide-reports="1" 
								</c:if>
								data-first-report="<c:out value="${ firstReport }"/>">
							<c:if test="${ not hasVulnerabilities }">
								<div class="alert alert-danger" style="margin-top:10px">
									<button class="close" data-dismiss="alert" type="button">×</button>
									<strong>No Vulnerabilities found.</strong> Upload a scan and try again.
								</div>
							</c:if>
						</div>
					</div>
				</div>
			</div>
		</div>
	
	</c:if>
</body>
