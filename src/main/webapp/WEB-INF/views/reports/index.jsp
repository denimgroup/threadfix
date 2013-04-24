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
	
				<div class="span4" style="float:left" id="formDiv">
				
				<h2>Reports</h2>
				
				<c:if test="${ not empty error }">
					<div class="alert">
						<button class="close" data-dismiss="alert" type="button">×</button>
						<c:out value="${ error }"/>
					</div>
				</c:if>
				
				<div id="helpText">This page is used to generate various reports.
				<br/>Please note that the Portfolio Report does not filter on a Team / Application basis and is only available in the HTML format.</div>
				
				<table class="table">
				<c:if test="${ not empty organizationList }">
					<form:form id="reportForm" modelAttribute="reportParameters"
									action="${ fn:escapeXml(emptyUrl) }">
						<tr class="reportFilterHeader">
							<th colspan="2">Filters</th>
						</tr>
						<tr>
							<td colspan="2">Team
								<span id="orgDropDown" style="float:right">
									<form:select style="margin-bottom:0px;width:190px;" path="organizationId"
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
							</td>
						</tr>
						<tr>
							<td colspan="2">Application
								<span id="appDropDown" style="float:right">
									<form:select style="margin-bottom:0px;width:190px;" path="applicationId"
											id="appSelect">
										<option value="-1">All</option>
									</form:select>
									<form:errors path="applicationId" />
								</span>
							</td>
						</tr>
					</form:form>
				</c:if>
				
					<tr class="reportFilterHeader">
						<th colspan="2">Report Type</th>
					</tr>
					<tr class="sidebar sidebar1 sidebar-active" data-report-id="1" data-url="<c:out value="${ emptyUrl }"/>">
						<td><a>Trending</a></td>
						<td><div class="sidebar-arrow sidebar-active" id="arrow1">&gt;</div></td>
					</tr>
					<tr class="sidebar sidebar2" data-report-id="2" data-url="<c:out value="${ emptyUrl }"/>">
						<td><a>Point in Time</a></td>
						<td><div class="sidebar-arrow" id="arrow2">&gt;</div></td>
					</tr>
					<tr class="sidebar sidebar3" data-report-id="3" data-url="<c:out value="${ emptyUrl }"/>">
						<td><a>Vulnerability Progress By Type</a></td>
						<td><div class="sidebar-arrow" id="arrow3">&gt;</div></td>
					</tr>
					<tr class="sidebar sidebar4" data-report-id="4" data-url="<c:out value="${ emptyUrl }"/>">
						<td><a>Channel Comparison By Vulnerability Types</a></td>
						<td><div class="sidebar-arrow"id="arrow4">&gt;</div></td>
					</tr>
					<tr class="sidebar sidebar5" data-report-id="5" data-url="<c:out value="${ emptyUrl }"/>">
						<td><a>Channel Comparison Summary</a></td>
						<td><div class="sidebar-arrow" id="arrow5">&gt;</div></td>
					</tr>
					<tr class="sidebar sidebar6" data-report-id="6" data-url="<c:out value="${ emptyUrl }"/>">
						<td ><a>Channel Comparison Detail</a></td>
						<td><div class="sidebar-arrow" id="arrow6">&gt;</div></td></tr>
					<tr class="sidebar sidebar7" data-report-id="7" data-url="<c:out value="${ emptyUrl }"/>">
						<td><a>Monthly Progress Report</a></td>
						<td><div class="sidebar-arrow" id="arrow7">&gt;</div></td>
					</tr>
					<tr class="sidebar sidebar8" data-report-id="8" data-url="<c:out value="${ emptyUrl }"/>">
						<td><a>Portfolio Report</a></td>
						<td><div class="sidebar-arrow" id="arrow8">&gt;</div></td>
					</tr>
					<tr class="sidebar sidebar9" data-report-id="9" data-url="<c:out value="${ emptyUrl }"/>">
						<td><a>Last 12 Months</a></td>
						<td><div class="sidebar-arrow" id="arrow9">&gt;</div></td>
					</tr>
					<tr class="sidebar sidebar10" data-report-id="10" data-url="<c:out value="${ emptyUrl }"/>">
						<td><a>Top Twenty Applications</a></td>
						<td><div class="sidebar-arrow" id="arrow10">&gt;</div></td>
					</tr>
				</table>
					
				</div>
				
				<div class="span8" id="successDiv" data-first-report="<c:out value="${ firstReport }"/>" style="margin-top:75px"></div>
			</div>
		</div>
	
	</c:if>
</body>
