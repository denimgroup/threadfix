<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Defect Trackers</title>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/defect-trackers-controller.js"></script>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/modal-controller-with-config.js"></script>
</head>

<body id="config">
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <div ng-controller="DefectTrackersController">
        <h2>Defect Trackers</h2>

        <%@ include file="/WEB-INF/views/successMessage.jspf" %>
        <%@ include file="modals/editDTModal.jsp" %>
        <%@ include file="modals/createDTModal.jsp" %>

        <div id="helpText">
            A Defect Tracker is the ThreadFix link that allows the user to bundle and export
            vulnerabilities from an Application to a Defect Tracker.
        </div>

        <button class="btn" ng-click="openNewModal()">Create New Tracker</button>

        <div ng-show="loading" style="float:right" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>

        <table ng-hide="loading" class="table table-striped">
            <thead>
                <tr>
                    <th class="medium first">Name</th>
                    <th class="long">URL</th>
                    <th>Type</th>
                    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_DEFECT_TRACKERS">
                        <th class="centered">Edit / Delete</th>
                    </security:authorize>
                </tr>
            </thead>
            <tbody>
                <tr ng-show="empty">
                    <td colspan="5" style="text-align:center;">No Defect Trackers found.</td>
                </tr>
                <tr ng-repeat="tracker in trackers">
                    <td id="defectTrackerName{{ $index }}">
                        {{ tracker.name }}
                    </td>
                    <td id="defectTrackerUrl{{ $index }}">
                        {{ tracker.url }}
                    </td>
                    <td id="defectTrackerType{{ $index }}">
                        {{ tracker.defectTrackerType.name }}
                    </td>
                    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_DEFECT_TRACKERS">
                        <td class="centered">
                            <a id="editDefectTracker{{ $index }}Button" class="btn" ng-click="openEditModal(tracker)">Edit / Delete</a>
                        </td>
                    </security:authorize>
                </tr>
            </tbody>
        </table>
    </div>
</body>