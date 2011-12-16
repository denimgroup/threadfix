<%@ include file="/common/taglibs.jsp"%>

<div id="logoBar"></div>
<div id="logo">
	<img src="<%=request.getContextPath()%>/images/hdr-threadfix-logo.png" class="transparent_png" alt="Threadfix" />
</div>
<div style="position:absolute; top:0%; left:0%; padding-top:10px; width:845px; color:#000; text-align:right">
	<table style="width:100%">
		<tr>
			<td id="logout" style="padding-right:15px">
				<spring:message code="user.status"/>
				<security:authentication property="principal.username"/> | 
				<strong><a id="logoutLink" href="<spring:url value="/j_spring_security_logout" htmlEscape="true" />">
					<spring:message code="user.logout"/>
				</a></strong>
			</td>
		</tr>
	</table>
</div>
<div id="menu">
	<table>
		<tbody>
			<tr>
				<td id="tab-apps" style="width: 90px;">
					<a id="orgHeader" href="<spring:url value="/organizations" htmlEscape="true"/>">Home</a>
				</td>
				<td id="tab-wafs" style="width: 90px;">
					<a id="wafsHeader" href="<spring:url value="/wafs" htmlEscape="true"/>">WAFs</a>
				</td>
				<td id="tab-reports" style="width: 110px;">
					<a id="reportsHeader" href="<spring:url value="/reports" htmlEscape="true"/>">Reports</a>
				</td>
				<td id="tab-config" style="width: 150px;">
					<a id="configurationHeader" href="<spring:url value="/configuration" htmlEscape="true"/>">Configuration</a>
				</td>
			</tr>
		</tbody>
	</table>
</div>