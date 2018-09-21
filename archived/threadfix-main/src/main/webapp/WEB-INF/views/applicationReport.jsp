<%@ include file="/common/taglibs.jsp"%>

<head>
<title><fmt:message key="mainMenu.title" /></title>
<meta name="heading" content="<fmt:message key='mainMenu.heading'/>" />
<meta name="menu" content="MainMenu" />


<style>
table, th, td, th {padding: 5px}
</style>

</head>

<div class="separator"></div>

<table>
<tr>
<!-- 
	<th>Date</th>
	-->
	<th>Scan ID</th>
	<th>Vulnerability Number</th>
	
	<c:forEach var="i" begin="1" end="${maxNum}">
		<th>${i}</th>
	</c:forEach>
	
<!-- 
	<th>Total</th>
	<th>New</th>
	<th>Old</th>
	<th>Resurfaced</th>
 -->
</tr>

<c:forEach var="vulnDataList" items="${scanVulnerabilityDataList}">
	<c:forEach var="data" items="${vulnDataList}" varStatus="status">
		<c:if test="${status.first}"><tr><td ng-non-bindable><c:out value="${ data }"/></td><td>Total</td></c:if>
		<c:if test="${not status.first}">
		<tr>
			<c:forEach var="i" begin="1" end="${data}" varStatus="i">
				<c:if test="${(status.index)==1}"><td style="background: black;">&nbsp;</td></c:if>	
				<c:if test="${(status.index)==2}"><td style="background: red;">&nbsp;</td></c:if>
				<c:if test="${(status.index)==3}"><td style="background: green;">&nbsp;</td></c:if>
				<c:if test="${(status.index)==4}"><td style="background: blue;">&nbsp;</td></c:if>
	     	</c:forEach>
	    </tr>
     	<tr>
	     	<c:if test="${(status.index)==1}"><td></td><td>New</td></c:if>
	     	<c:if test="${(status.index)==2}"><td></td><td>Old</td></c:if>
	     	<c:if test="${(status.index)==3}"><td></td><td>Resurfaced</td></c:if>
     	</c:if>
	</c:forEach>
	<tr><td>&nbsp;</td></tr> <!--  Spacer  -->
</c:forEach>

</table>