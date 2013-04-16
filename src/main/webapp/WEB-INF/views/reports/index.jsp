<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Reports</title>
	
	<spring:url value="/reports/ajax" var="emptyUrl"></spring:url>	
	
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/report_page.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/ajax_replace.js"></script>
	<script type="text/javascript">
	$(document).ready(function(){ 
		$("#orgSelect").change(function() {
			$("#appSelect").html('');
			$("#appSelect").append('<option value="-1">All</option>');
			var options = '';
			
			<c:forEach var="organization" items="${organizationList}">
			    if("${organization.id}" == $("#orgSelect").val()) {
					<c:forEach var="application" items="${ organization.activeApplications}">
						options += '<option value="${ application.id}"><c:out value="${ application.name }"/></option>';
					</c:forEach>
			    }
			</c:forEach>

			$("#appSelect").append(options);
			reload('<c:out value="${ emptyUrl }"/>');
		});
		$("#appSelect").change(function() {
			reload('<c:out value="${ emptyUrl }"/>');
		});
	});
	</script>

</head>

<body id="reports">
	
	<%@ include file="/WEB-INF/views/errorMessage.jsp" %>
	
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
													id="orgSelect">
												<option value="-1">All</option>
												<c:forEach var="organization" items="${ organizationList }">
													<c:if test="${ organization.active }">
													<option value="${ organization.id }">
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
					<tr class="sidebar sidebar1 sidebar-active" onclick="javascript:selectReportType('<c:out value="${ emptyUrl }"/>', '1')">
						<td><a>Trending</a></td>
						<td><div class="sidebar-arrow sidebar-active" id="arrow1">&gt;</div></td>
					</tr>
					<tr class="sidebar sidebar2" onclick="javascript:selectReportType('<c:out value="${ emptyUrl }"/>', '2')">
						<td><a>Point in Time</a></td>
						<td><div class="sidebar-arrow" id="arrow2">&gt;</div></td>
					</tr>
					<tr class="sidebar sidebar3" onclick="javascript:selectReportType('<c:out value="${ emptyUrl }"/>', '3')">
						<td><a>Vulnerability Progress By Type</a></td>
						<td><div class="sidebar-arrow" id="arrow3">&gt;</div></td>
					</tr>
					<tr class="sidebar sidebar4" onclick="javascript:selectReportType('<c:out value="${ emptyUrl }"/>', '4')">
						<td><a>Channel Comparison By Vulnerability Types</a></td>
						<td><div class="sidebar-arrow"id="arrow4">&gt;</div></td>
					</tr>
					<tr class="sidebar sidebar5" onclick="javascript:selectReportType('<c:out value="${ emptyUrl }"/>', '5')">
						<td><a>Channel Comparison Summary</a></td>
						<td><div class="sidebar-arrow" id="arrow5">&gt;</div></td>
					</tr>
					<tr class="sidebar sidebar6" onclick="javascript:selectReportType('<c:out value="${ emptyUrl }"/>', '6')">
						<td ><a>Channel Comparison Detail</a></td>
						<td><div class="sidebar-arrow" id="arrow6">&gt;</div></td></tr>
					<tr class="sidebar sidebar7" onclick="javascript:selectReportType('<c:out value="${ emptyUrl }"/>', '7')">
						<td><a>Monthly Progress Report</a></td>
						<td><div class="sidebar-arrow" id="arrow7">&gt;</div></td>
					</tr>
					<tr class="sidebar sidebar8" onclick="javascript:selectReportType('<c:out value="${ emptyUrl }"/>', '8')">
						<td><a>Portfolio Report</a></td>
						<td><div class="sidebar-arrow" id="arrow8">&gt;</div></td>
					</tr>
				</table>
				
				<script>
					javascript:submitAjaxReport('<c:out value="${ emptyUrl }"/>', '#reportForm', '#formDiv', '#successDiv', 1, 1);
				</script>
					
					</div>
				
				<div class="span8" id="successDiv" style="margin-top:75px"></div>
			</div>
		</div>
	
	</c:if>
</body>
