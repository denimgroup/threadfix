<%--<div ng-controller="VulnerabilityCommentsTableController">--%>
<div>

    <div ng-form="mappedForm" class="pagination" ng-show="numVulns > numberToShow">
        <pagination class="no-margin" id ="{{vulnType}}Pagination"
                    total-items="numVulns / numberToShow * 10"
                    max-size="5"
                    page="page"
                    ng-model="page"
                    ng-click="init()"></pagination>

        <input name="pageMappedInput"  ng-enter="goToPage(mappedForm.$valid)" style="width:50px" type="number" ng-model="pageInput" max="{{numberOfPages * 1}}" min="1"/>
        <button class="btn" ng-class="{ disabled : mappedForm.$invalid }" ng-click="goToPage(mappedForm.$valid)"> Go to Page </button>
        <span class="errors" ng-show="mappedForm.pageMappedInput.$dirty && mappedForm.pageMappedInput.$error.min || mappedForm.pageMappedInput.$error.max">Input number from 1 to {{numberOfPages}}</span>
        <span class="errors" ng-show="mappedForm.pageMappedInput.$dirty && mappedForm.pageMappedInput.$error.number">Not a valid number</span>
    </div>

    <div ng-show="loading" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <div ng-hide="vulnList">
        No Vulnerabilities Found.
    </div>

    <div style="padding-bottom:10px">
        <a ng-show="vulnList" class="btn" id="{{vulnType}}ExpandAllButton" ng-click="expand(vulnList)">Expand All</a>
        <a ng-show="vulnList" class="btn" id="{{vulnType}}CollapseAllButton" ng-click="contract(vulnList)">Collapse All</a>
    </div>

    <table ng-show="vulnList" class="table table-hover white-inner-table">
        <thead>
        <tr>
            <th style="width:8px"></th>
            <th style="width:300px;">Vulnerability Name</th>
            <th class="centered">Severity</th>
            <th class="centered">Application</th>
            <th class="centered">Team</th>
            <th style="width:70px;"></th>
        </tr>
        </thead>
        <tbody>

        <tr ng-repeat-start="vuln in vulnList" id="vulnRow{{ $index }}" class="pointer">
            <td id="vulnCaret{{ $index }}" ng-click="toggle(vuln)">
                <span ng-class="{ expanded: vuln.expanded }" class="caret-right"></span>
            </td>
            <td ng-click="toggle(vuln)" id="vulnName{{ $index }}" style="word-wrap: break-word;text-align:left;">
                {{ vuln.genericVulnerability.name }}
            </td>
            <td ng-click="toggle(vuln)" class="centered" id="severity{{ $index }}"
                ng-class="{
                        'badge-critical': vuln.genericSeverity.intValue === 5,
                        'badge-high': vuln.genericSeverity.intValue === 4,
                        'badge-medium': vuln.genericSeverity.intValue === 3,
                        'badge-low': vuln.genericSeverity.intValue === 2,
                        'badge-info': vuln.genericSeverity.intValue === 1
                        }">{{ vuln.genericSeverity.name }}</td>
            <td style="word-wrap: break-word;" class="centered" id="appName{{ $index }}"><a ng-click="goToAppFromVuln(vuln)">{{ vuln.app.name }}</a></td>
            <td style="word-wrap: break-word;" class="centered" id="teamName{{ $index }}"><a ng-click="goToTeamFromVuln(vuln)">{{ vuln.team.name }}</a></td>
            <td>
                <a style="text-decoration:none" id="vulnLink{{ $index }}" ng-click="goToVuln(vuln)">View More</a>
            </td>
        </tr>

        <tr ng-repeat-end class="grey-background" id="comments{{ $index }}">
            <td colspan="6">
                <div collapse="!vuln.expanded"
                     id="vulnInfoDiv{{ $index }}"
                     class="collapse vulnerabilitySection"
                     ng-class="{ expanded: vuln.expanded }">

                    <div style="text-align: center;" ng-hide="vuln.vulnerabilityComments">
                        No Comments Found.
                    </div>

                    <div ng-show='vuln.vulnerabilityComments'>
                        <table id="vulnCommentTable{{ $index }}">
                            <thead>
                            <tr>
                                <th>User</th>
                                <th>Date</th>
                                <th>Comment</th>
                                <th>Tag</th>
                            <tr>
                            </thead>
                            <tbody>
                            <tr ng-repeat="comment in vuln.vulnerabilityComments" class="bodyRow left-align">
                                <td id="commentUser{{ $index }}">{{ comment.username }}</td>
                                <td id="commentDate{{ $index }}">{{ comment.time | date:'yyyy-MM-dd HH:mm' }}</td>
                                <td id="commentText{{ $index }}">
                                    <div class="vuln-comment-word-wrap">
                                        {{ comment.comment }}
                                    </div>
                                </td>
                                <td class="left-align" >
                        <span ng-repeat="cmtTag in comment.tags">
                            <a class="pointer" id="cmtTag{{ $index }}" ng-click="goToTag(cmtTag)">{{cmtTag.name}}<span ng-hide="$index===comment.tags.length-1">,</span></a>
                        </span>
                                </td>
                            </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </td>
        </tr>
        </tbody>
    </table>
</div>