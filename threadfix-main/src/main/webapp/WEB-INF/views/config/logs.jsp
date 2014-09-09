<%@ include file="/common/taglibs.jsp"%>
<%@ taglib prefix="cbs" uri="/WEB-INF/jscachebust.tld"%>

<head>
	<title>Logs</title>
	<cbs:cachebustscript src="/scripts/toggle.js"/>
	<cbs:cachebustscript src="/scripts/error-logs-controller.js"/>
</head>

<body ng-controller="ErrorLogsController" ng-init="initialId = '<c:out value="log.id"/>'">

    <%@ include file="../angular-init.jspf"%>

	<h3>Log List (Click to expand)</h3>

    <div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div>

    <div ng-show="initialized" class="pagination" ng-init="page = 1">
        <pagination class="no-margin"
                    total-items="totalLogs / 5"
                    max-size="5"
                    page="page"
                    ng-model="page"
                    ng-change="updatePage(page)"></pagination>
    </div>
    <br>

	<a ng-repeat-start="log in logs" class="pointer" ng-click="log.expanded = !log.expanded">
        {{ log.time | date }} -- {{ log.uuid }} -- {{ log.type }}
    </a>
			
    <span ng-repeat-end id="{{ $index }}">
        <pre ng-show="log.expanded">{{ log.exceptionStackTrace }}</pre>
        <br>
    </span>

</body>