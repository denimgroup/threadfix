<%@ include file="/common/taglibs.jsp"%>

<ul class="breadcrumb">
    <li><a href="<spring:url value="/teams"/>">Applications Index</a><span class="divider">/</span></li>
    <li><a ng-click="goToTeam()">Team: {{ finding.team.name }}</a> <span class="divider">/</span></li>
    <li><a ng-click="goToApplication()">Application: {{ finding.application.name }}</a><span class="divider">/</span></li>
    <li><a ng-click="goToScan()">{{ finding.scan.importTime | date:'shortDate'}} {{ finding.scan.importTime | date:'shortTime'}} {{ finding.scan.name }} Scan</a><span class="divider">/</span></li>
    <li class="active">Finding {{ finding.id }}</li>
</ul>