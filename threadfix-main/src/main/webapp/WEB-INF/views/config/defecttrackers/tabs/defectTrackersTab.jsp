<%@ include file="/common/taglibs.jsp"%>

<tab id="defectTrackersTab" ng-controller="DefectTrackersTabController" heading="{{ heading }}">
    <%@ include file="/WEB-INF/views/successMessage.jspf" %>
    <%@ include file="../modals/editDTModal.jsp" %>
    <%@ include file="../modals/createDTModal.jsp" %>
    <%@ include file="../modals/updateDefectDefaultModal.jsp" %>
    <%@ include file="../modals/createDefaultProfileModal.jsp" %>

    <div id="helpText">
        A Defect Tracker is the ThreadFix link that allows the user to bundle and export
        vulnerabilities from an Application to a Defect Tracker.
    </div>

    <button class="btn" id="addNewDTButton" ng-click="openNewModal()">Create New Tracker</button>

    <div ng-show="loading" style="float:right" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>

    <table id="defectTrackerTableBody" ng-hide="loading" class="table"> <!-- table-striped class removed -->
        <thead>
        <tr>
            <th class="medium first">Name</th>
            <th class="long">URL</th>
            <th>Type</th>
            <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_DEFECT_TRACKERS">
                <th class="centered">Defect Defaults</th>
                <th class="centered">Edit / Delete</th>
            </security:authorize>
        </tr>
        </thead>
        <tbody>
        <tr ng-show="empty">
            <td colspan="5" style="text-align:center;">No Defect Trackers found.</td>
        </tr>
        <tr ng-repeat-start="tracker in trackers">
            <td id="defectTrackerName{{ tracker.name }}">
                {{ tracker.name }}
            </td>
            <td id="defectTrackerUrl{{ tracker.name }}">
                {{ tracker.url }}
            </td>
            <td id="defectTrackerType{{ tracker.name }}">
                {{ tracker.defectTrackerType.name }}
            </td>
            <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_DEFECT_TRACKERS">
                <td class="centered">
                     <a id="showDefaultProfilesButton{{ tracker.name }}" class="btn" ng-click="showDefaultProfiles(tracker)">Show Default Profiles</a>
                </td>
                <td class="centered">
                    <a id="editDefectTrackerButton{{ tracker.name }}" class="btn" ng-click="openEditModal(tracker)">Edit / Delete</a>
                </td>
            </security:authorize>
        </tr>
		<tr ng-repeat-end ng-show="tracker.showDefaultProfiles"
			class="grey-background">
			<td colspan="4">
				<table>
					<thead ng-show="tracker.defaultDefectProfiles.length > 0">
						<tr>
							<th>Profile</th>
							<th>Reference Application</th>
							<th class="centered">Update Defect Defaults</th>
							<th class="centered">Delete Profile</th>
						</tr>
					</thead>
					<tbody>
						<tr ng-repeat="defaultProfile in tracker.defaultDefectProfiles">
							<td>{{ defaultProfile.name }}</td>
							<td>{{ defaultProfile.referenceApplication.name }}</td>
							<td><a class="centered btn"	ng-click="openUpdateDefectDefaultsModal(defaultProfile)">Set Defaults</a>
							</td>
							<td><a class="centered btn" ng-click="deleteDefaultProfile(tracker,defaultProfile)">Delete Profile</a></td>
						</tr>
						<tr
							ng-show="tracker.defaultDefectProfiles.length==0 && tracker.showDefaultProfiles">
							<td>No existing profiles</td>
						</tr>
						<tr>
							<td>
							     <a class="btn"	ng-click="openCreateProfileModal(tracker)">Create Profile</a>
							     <span ng-show="isMissingApplication[tracker.id]" class="errors">Cannot	create profile. No application attached to this tracker</span>
						    </td>
						</tr>
					</tbody>
				</table>
			</td>
		</tr>
	</tbody>
    </table>
</tab>