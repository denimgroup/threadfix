<%@ include file="/common/taglibs.jsp"%>

<div id="scanQueueDiv${ application.id }">
	<table class="table">
        <thead>
            <tr>
                <th id="scanQueueTable">ID</th>
                <th>Status</th>
                <th>Scanner</th>
                <th>Created Time</th>
                <th>Start Time</th>
                <th>End Time</th>
                <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_SCAN_AGENTS">
                    <th class="centered last"></th>
                </security:authorize>
            </tr>
        </thead>
        <tbody>
            <tr ng-hide="scanAgentTasks" class="bodyRow">
                <td colspan="7" style="text-align:center;">No Scan Agent Tasks found.</td>
            </tr>
            <tr class="bodyRow" ng-repeat="task in scanAgentTasks">
                <td>
                    <a id="goToTaskLink{{ $index }}" class="pointer" ng-click="goTo(task)">
                        {{ task.id }}
                    </a>
                </td>
                <td id="statusString{{ $index }}">{{ task.statusString }}</td>
                <td id="scannerType{{ $index }}"> {{ task.scanner }}</td>
                <td id="createTime{{ $index }}">{{ task.createTime | date:'MMM d, y h:mm:ss a' }}</td>
                <td id="startTime{{ $index }}">{{ task.startTime | date:'MMM d, y h:mm:ss a' }}</td>
                <td id="endTime{{ $index }}">{{ task.endTime | date:'MMM d, y h:mm:ss a' }}</td>
                <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_SCAN_AGENTS">
                    <td class="centered">
                        <a id="deleteButton{{ $index }}" class="btn btn-danger" ng-click="deleteScanAgentTask(task)">Delete</a>
                    </td>
                </security:authorize>
            </tr>
        </tbody>
	</table>
</div>