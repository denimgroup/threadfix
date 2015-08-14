<div class="accordion-inner" ng-repeat="vulnerability in element.vulns">
    <span ng-hide="treeApplication">
        <p><b> {{ $index + 1 }} / {{ element.numResults }} {{ category.name }} {{ element.genericVulnerability.name | shortCweNames }} </b></p>
        <div><b>Application </b> {{ treeTeam ? "" : vulnerability.team.name }} / {{ vulnerability.app.name }}</div>
    </span>

    <!-- Path + Parameter -->
    <div ng-if="!vulnerability.dependency">
        <div ng-if="vulnerability.path || vulnerability.parameter">
            <div><b>Path </b> {{ vulnerability.path }}</div>
            <div><b>Parameter </b> {{ vulnerability.parameter }}</div>
        </div>
        <div ng-if="vulnerability.calculatedFilePath">
            <div><b>File </b> {{ vulnerability.calculatedFilePath }}</div>
        </div>
    </div>

    <!-- Dependency -->
    <div ng-if="vulnerability.dependency">
        <div><b>Reference </b> {{ vulnerability.dependency.refId }}</div>
        <div><b>Component </b> {{ vulnerability.dependency.componentName }}</div>
        <div><b>Description </b> {{ vulnerability.dependency.description }}</div>
    </div>

    <!-- Scanner Badges -->
    <span id="channel{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}{{ name }}" ng-repeat="name in vulnerability.channelNames" class="badge">{{ name }}</span>
    <a id="defectBadge{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}"
       ng-href="{{ vulnerability.defect.defectURL }}"
       target="_blank"
       ng-if="vulnerability.defect"
       ng-class="{
        'badge-critical': vulnerability.defect.opened,
        'badge-low': !vulnerability.defect.opened,
        }"
       class="badge">
        Issue {{ vulnerability.defect.nativeId }} ({{ vulnerability.defect.status }})
    </a>
    <br ng-if="vulnerability.defect">

    <a id="grcControlBadge{{ element.genericVulnerability.displayId }}{{ $index }}"
       ng-href="{{ vulnerability.grcControl.referenceUrl }}"
       target="_blank"
       ng-if="vulnerability.grcControl"
       ng-class="{
        'badge-critical': vulnerability.grcControl.bugImageName === 'icn_bug_red_stroke.png',
        'badge-low': vulnerability.grcControl.bugImageName === 'icn_bug_grn_stroke.png',
        }"
       class="badge">
        Control {{ vulnerability.grcControl.controlId }} ({{ vulnerability.grcControl.status }})
    </a>
    <br ng-if="vulnerability.grcControl">

    <!-- Comments body -->
    <div ng-if="vulnerability.vulnerabilityComments" style="display:inline-block">
        <div><b>Comments</b></div>
        <table class="table">
            <thead>
            <tr>
                <th>User</th>
                <th>Date</th>
                <th>Comment</th>
                <th>Tag</th>
            <tr>
            </thead>
            <tbody>
            <tr ng-repeat="comment in vulnerability.vulnerabilityComments" class="bodyRow left-align">
                <td>{{ comment.username }}</td>
                <td>{{ comment.time | date:'yyyy-MM-dd HH:mm' }}</td>
                <td>
                    <div class="vuln-comment-word-wrap">
                        {{ comment.comment }}
                    </div>
                </td>
                <td class="left-align" >
                    <span ng-repeat="cmtTag in comment.tags">{{cmtTag.name}}<span ng-if="$index===comment.tags.length-1">,&nbsp;</span></span>
                </td>
            </tr>
            </tbody>
        </table>
    </div>

    <!-- Documents body -->
    <br ng-if="vulnerability.documents && vulnerability.documents.length > 0">
    <div ng-if="vulnerability.documents && vulnerability.documents.length > 0">
        <div><b>Files</b></div>
        <table class="table">
            <thead>
            <tr>
                <th class="first">File Name</th>
                <th>Type</th>
                <th>Upload Date</th>
            </tr>
            </thead>
            <tbody>
            <tr ng-repeat="document in vulnerability.documents" class="bodyRow left-align">
                <td>{{ document.name }}</td>
                <td>{{ document.type }}</td>
                <td>{{ document.uploadedDate  | date:'yyyy-MM-dd HH:mm' }}</td>
            </tr>
            </tbody>
        </table>
    </div>

    <!-- Data Flow and Request/Response body  -->
    <br >
    <div >

        <div ng-if="vulnerability.staticFindings.length > 1">
            <div><b>Data Flow Variants</b></div>
            <div ng-repeat="finding in vulnerability.staticFindings" ng-if="finding.dataFlowElements">
                <div id='dataFlow{{ finding.id }}'>
                    <h5>
                        Finding
                        {{ finding.id }}
                        Data Flow (Elements: {{ finding.dataFlowElements.length }})
                    </h5>
                    <div ng-repeat="dataFlowElement in finding.dataFlowElements">

                        <div>{{ dataFlowElement.sourceFileName }} line {{ dataFlowElement.lineNumber }}</div>
                        <div>
                            <pre>{{ dataFlowElement.lineText }}</pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div ng-if="vulnerability.staticFindings.length === 1">
            <div><b>Data Flow</b></div>
            <div ng-repeat="dataFlowElement in vulnerability.staticFindings[0].dataFlowElements">
                <div>{{ dataFlowElement.sourceFileName }} line {{ dataFlowElement.lineNumber }}</div>
                <div>
                    <pre>{{ dataFlowElement.lineText }}</pre>
                </div>
            </div>
        </div>


        <div ng-if="vulnerability.dynamicFindings.length > 1">
            <div><b>Request Variants</b></div>
            <br>
            <div ng-repeat="finding in vulnerability.dynamicFindings">
                <div id='{{ finding.id }}'>
                    <h5>
                        Finding
                        {{ finding.id }}
                        Attack
                    </h5>
                    <div style="word-wrap: break-word;" class="inputValue"><b>Attack Request </b>
                        <PRE>{{ finding.attackRequest }}</PRE>
                    </div>
                    <div style="word-wrap: break-word;" class="inputValue"><b>Attack Response </b>
                        <PRE>{{ finding.attackResponse }}</PRE>
                    </div>
                </div>
            </div>
        </div>

        <div ng-if="vulnerability.dynamicFindings.length === 1">
            <div><b>Request</b></div>
            <div style="word-wrap: break-word;"><b>Attack Request </b>
                <PRE>{{ vulnerability.dynamicFindings[0].attackRequest }}</PRE>
            </div>
            <div style="word-wrap: break-word;"><b>Attack Response </b>
                <PRE>{{ vulnerability.dynamicFindings[0].attackResponse }}</PRE>
            </div>
        </div>
    </div>

</div>