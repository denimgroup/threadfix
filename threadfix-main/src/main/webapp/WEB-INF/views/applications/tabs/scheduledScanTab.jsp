<%@ include file="/common/taglibs.jsp"%>

<c:if test="${ canManageApplications && fn:length(scannerTypeList) > 0 }">
    <div style="margin-top:10px;margin-bottom:7px;">
        <a id="addScanQueueLink" class="btn" ng-click="openNewScheduledScanModal()">Schedule New Scan</a>
    </div>
</c:if>

<div id="scheduledScanDiv${ application.id }">
	<table class="table" id="scheduledScanTable">
        <thead>
            <tr>
                <th>ID</th>
                <th>Scanner</th>
                <th>Profile</th>
                <th>Target URL</th>
                <th>Time</th>
                <th>Frequency</th>
                <th>Cron Expression</th>
                <c:if test="${ canManageApplications }">
                    <th class="centered last"></th>
                </c:if>
            </tr>
        </thead>
        <tbody>
            <tr ng-hide="scheduledScans" class="bodyRow">
                <td id="noScheduledScansFoundMessage" colspan="5" style="text-align:center;">No Scheduled Scans found.</td>
            </tr>
            <tr class="bodyRow" ng-repeat="scheduledScan in scheduledScans">
                <td id="scheduledScanId{{ $index }}"> {{ scheduledScan.id }} </td>
                <td id="scheduledScanScanner{{ $index }}"> {{ scheduledScan.scanner }} </td>
                <td id="scheduledScanScanner{{ $index }}"><span ng-show="scheduledScan.scanConfig"> {{ scheduledScan.scanConfig.name + '.' + scheduledScan.scanConfig.type }} </span></td>
                <td id="scheduledScanTargetUrl{{ $index }}"> {{ scheduledScan.targetUrl }} </td>
                <td id="scheduledScanDay{{ $index }}">
                    <span ng-hide="scheduledScan.scheduleType == 'CRON'">
                        {{ scheduledScan.day }}&nbsp;{{ (scheduledScan.hour == 0) ? '12' : scheduledScan.hour }}:{{ scheduledScan.extraMinute }}{{ scheduledScan.minute }}&nbsp;{{ scheduledScan.period }}
                    </span>
                </td>
                <td id="scheduledScanFrequency{{ $index }}">
                    <span ng-hide="scheduledScan.scheduleType == 'CRON'">
                        {{ scheduledScan.frequency }}
                    </span>
                </td>
                <td id="scheduledScanCronExpression{{ $index }}">
                    <span ng-show="scheduledScan.scheduleType == 'CRON'" tooltip="{{ scheduledUpdate.cronTranslation }}">
                        {{ scheduledScan.cronExpression }}
                    </span>
                </td>
                <c:if test="${ canManageApplications }">
                    <td class="centered">
                        <a  id="scheduledScanDeleteButton{{ $index }}" class="btn btn-danger" ng-click="deleteScheduledScan(scheduledScan)">Delete</a>
                    </td>
                </c:if>
            </tr>
        </tbody>
	</table>
    <div>
        Use <a href="https://crontranslator.appspot.com/">Cron Translator</a> to decode cron expressions
    </div>
</div>