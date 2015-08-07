
<tab id="documentsTab" ng-controller="DocumentFormController" heading="{{ heading }}" ng-click="setTab('Files')" active="tab.files">

    <c:if test="${ canManageApplications }">
        <div style="margin-top:10px;margin-bottom:7px;">
            <a id="uploadDocModalLink${ application.id }" class="btn" ng-click="showUploadForm()">Add File</a>
        </div>
    </c:if>

    <table ng-show="documents" class="table table-striped">
        <thead>
            <tr>
                <th class="first">ID</th>
                <th>File Name</th>
                <th>Type</th>
                <th>Upload Date</th>
                <th class="centered">Download</th>
                <c:if test="${ canManageApplications }">
                    <th class="centered last">Delete</th>
                </c:if>
                <th></th>
            </tr>
        </thead>
        <tbody>
            <tr ng-repeat="document in documents" class="bodyRow">
                <td id="docId{{ $index }}">{{ document.id }}</td>
                <td id="docName{{ $index }}">{{ document.name }}</td>
                <td id="type{{ $index }}" >{{ document.type }}</td>
                <td id="uploadDate{{ $index }}" >
                    {{ document.uploadedDate | date:'medium' }}
                </td>
                <td class="centered">
                    <a target="_blank" class="btn" type="submit" ng-href="{{ base }}/documents/{{ document.id }}/download{{ csrfToken }}">Download</a>
                </td>
                <c:if test="${ canManageApplications }">
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
</tab>