<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Logs</title>
	<cbs:cachebustscript src="/scripts/toggle.js"/>
	<cbs:cachebustscript src="/scripts/error-logs-controller.js"/>
</head>

<body ng-controller="ErrorLogsController" ng-init="initialId = '<c:out value="log.id"/>'">

    <%@ include file="../angular-init.jspf"%>

    <h3>Error Messages <span ng-show="totalLogs !== 0">(Click to expand)</span></h3>

    <div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div>

    <div ng-show="totalLogs === 0">
        <span>No Logs Found.</span>
    </div>
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

    <table id="logListTable">
        <tbody>
        <tr ng-repeat-start="log in logs" >
            <td id="logId{{ $index }}">
                <a class="pointer" ng-click="log.expanded = !log.expanded">{{ log.time | date:'MMM d, y h:mm:ss a' }} -- {{ log.type }}</a>
            </td>
            <td id="reportLink{{ $index }}" style="padding-left: 5em">
                <a class="pointer" ng-click="log.expanded = true"
                   href="mailto:support@threadfix.org?subject={{ log.time | date : 'medium' }} -- {{ log.type }}
                   &body=***** Please copy log trace here *****">
                   Report To ThreadFix Team</a>
            </td>

        </tr>
        <tr ng-repeat-end>
            <td colspan="2" id="logContent{{ $index }}">
                <pre ng-show="log.expanded">Commit: {{ log.commit }}
Diagnostics: {{ log.freeMemory }} memory available out of {{ log.totalMemory }}. {{ log.freeDiskSpace }} disk space available.

{{ log.exceptionStackTrace }}
                </pre>
            </td>

        </tr>
        </tbody>
    </table>

</body>