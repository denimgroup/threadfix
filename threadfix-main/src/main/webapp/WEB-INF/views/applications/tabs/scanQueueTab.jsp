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
                <c:if test="${ canManageApplications }">
                    <th class="centered last"></th>
                </c:if>
            </tr>
        </thead>
        <tbody>
            <tr ng-hide="scanAgentTasks" class="bodyRow">
                <td colspan="7" style="text-align:center;">No Scan Agent Tasks found.</td>
            </tr>
            <tr class="bodyRow" ng-repeat="task in scanAgentTasks">
                <td>
                    <a id="scanAgentTask{{ $index }}" class="pointer" ng-click="goTo(task)">
                        {{ task.id }}
                    </a>
                </td>
                <td id="scanAgentTaskStatusString{{ $index }}">{{ task.statusString }}</td>
                <td id="scannerType{{ $index }}"> {{ task.scanner }}</td>
                <td id="scanAgentTaskCreateTime{{ $index }}">{{ task.createTime | date:'MMM d, y h:mm:ss a' }}</td>
                <td id="scanAgentTaskStartTime{{ $index }}">{{ task.startTime | date:'MMM d, y h:mm:ss a' }}</td>
                <td id="scanAgentTaskEndTime{{ $index }}">{{ task.endTime | date:'MMM d, y h:mm:ss a' }}</td>
                <c:if test="${ canManageApplications }">
                    <td class="centered">
                        <a id="deleteButton{{ $index }}" class="btn btn-danger" ng-click="deleteScanAgentTask(task)">Delete</a>
                    </td>
                </c:if>
            </tr>
        </tbody>
	</table>
</div>