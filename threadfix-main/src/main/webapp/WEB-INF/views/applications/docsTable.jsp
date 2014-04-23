<table class="table">
	<thead>
		<tr>
			<th class="first"></th>
			<th>File Name</th>
			<th>Type</th>
			<th>Upload Date</th>
			<th class="centered">Download</th>
            <c:if test="${ canModifyVulnerabilities }">
			    <th class="centered last">Delete</th>
            </c:if>
			<th></th>
		</tr>
	</thead>
	<tbody id="wafTableBody">
        <tr ng-hide="documents" class="bodyRow">
            <td colspan="7" style="text-align:center;">No files found.</td>
        </tr>
        <tr ng-show="documents" ng-repeat="document in documents" class="bodyRow">
            <td id="docNum{{ $index }}">{{ $index + 1 }}</td>
            <td id="name{{ $index }}">{{ document.name }}</td>
            <td id="type{{ $index }}">{{ document.type }}</td>
            <td id="uploadDate{{ $index }}" >{{ document.uploadedDate | date:'yyyy-MM-dd HH:mm' }}</td>
            <td class="centered">
                <a target="_blank" class="btn" type="submit" ng-href="{{ base }}/documents/{{ document.id }}/download{{ csrfToken }}">Download</a>
            </td>
            <c:if test="${ canModifyVulnerabilities }">
                <td class="centered">
                    <a ng-hide="document.deleting" class="btn btn-danger" ng-click="deleteFile(document)">Delete</a>
                    <a ng-show="document.deleting" class="btn btn-danger" ng-disabled>
                        <span class="spinner"></span>
                        Deleting
                    </a>
                </td>
            </c:if>
            <td>
                <a ng-href="{{ base }}/documents/{{ document.id }}/view{{ csrfToken }}" target="_blank">View File</a>
            </td>
        </tr>
	</tbody>
</table>
