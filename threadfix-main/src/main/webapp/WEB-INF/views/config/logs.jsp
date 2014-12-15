<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Logs</title>
	<cbs:cachebustscript src="/scripts/toggle.js"/>
	<cbs:cachebustscript src="/scripts/error-logs-controller.js"/>
</head>

<body ng-controller="ErrorLogsController" ng-init="initialId = '<c:out value="log.id"/>'">

    <%@ include file="../angular-init.jspf"%>

    <h3>Log List (Click to expand)</h3>

    <div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div>

    <div ng-show="totalLogs > numberToShow" class="pagination" ng-init="page = 1">
        <pagination id="logPagination"
                    class="no-margin"
                    total-items="totalLogs / numberToShow * 10"
                    max-size="5"
                    page="page"
                    ng-model="page"
                    ng-click="updatePage(page)"></pagination>
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