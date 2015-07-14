<div ng-show="type === 'VULNERABILITY'">

    <h4 style="padding-top:10px">Tagged Vulnerabilities</h4>

    <div ng-form="mappedForm" class="pagination" ng-show="numVulns > numberToShow">
        <pagination class="no-margin" id ="vulnTablePagination"
                    total-items="numVulns / numberToShow * 10"
                    max-size="5"
                    page="vulnPage"
                    ng-model="vulnPage"
                    ng-click="init(vulnPage)"></pagination>

        <input name="vulnPageMappedInput"  ng-enter="goToPage(mappedForm.$valid, vulnPageInput)" style="width:50px" type="text" ng-model="vulnPageInput" max="{{numberOfPages * 1}}" min="1"/>
        <button class="btn" ng-class="{ disabled : mappedForm.$invalid }" ng-click="goToPage(mappedForm.$valid)"> Go to Page </button>
        <span class="errors" ng-show="mappedForm.pageMappedInput.$dirty && mappedForm.pageMappedInput.$error.min || mappedForm.pageMappedInput.$error.max">Input number from 1 to {{numberOfPages}}</span>
        <span class="errors" ng-show="mappedForm.pageMappedInput.$dirty && mappedForm.pageMappedInput.$error.number">Not a valid number</span>
    </div>

    <div ng-show="loading" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <div ng-hide="vulnListOfVulnTags">
        No Vulnerabilities Found.
    </div>

    <div style="padding-bottom:10px">
        <a ng-show="vulnListOfVulnTags" class="btn" id="{{vulnType}}ExpandAllButton" ng-click="expand(vulnListOfVulnTags)">Expand All</a>
        <a ng-show="vulnListOfVulnTags" class="btn" id="{{vulnType}}CollapseAllButton" ng-click="contract(vulnListOfVulnTags)">Collapse All</a>
    </div>

    <table ng-show="vulnListOfVulnTags" class="table table-hover white-inner-table">
        <thead>
        <tr>
            <th style="width:8px"></th>
            <th style="width:300px;">Vulnerability Name</th>
            <th class="centered">Severity</th>
            <th ng-hide="vuln.originalFinding.dependency">
                Path
            </th>
            <th ng-hide="vuln.originalFinding.dependency">
                Parameter
            </th>
            <th ng-show="vuln.originalFinding.dependency">
                Reference
            </th>
            <th style="width:70px;"></th>
        </tr>
        </thead>
        <tbody>

        <tr ng-repeat-start="vuln in vulnListOfVulnTags" id="vulnRow{{ $index }}" class="pointer">
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
            <td ng-click="toggle(vuln)" ng-hide="vuln.originalFinding.dependency">{{ vuln.path }}</td>
            <td ng-click="toggle(vuln)" ng-hide="vuln.originalFinding.dependency">{{ vuln.parameter }}</td>
            <td ng-show="vuln.originalFinding.dependency">
                <a target="_blank" id="linkCve" href="{{ vuln.originalFinding.dependency.refLink }}">{{ vuln.originalFinding.dependency.refId }}</a>
            </td>
            <td><a style="text-decoration:none" id="vulnLink{{ $index }}" ng-click="goToVuln(vuln)">View More</a></td>
        </tr>

        <tr ng-repeat-end class="grey-background">
            <td colspan="3">
                <div collapse="!vuln.expanded"
                     id="vulnDiv{{ $index }}"
                     class="collapse vulnerabilitySection"
                     ng-class="{ expanded: vuln.expanded }">
                    <table id="vulTable{{ $index }}">
                        <thead>
                        <tr>
                            <th>Application</th>
                            <th>Team</th>
                            <th>Tag</th>
                        <tr>
                        </thead>
                        <tbody>
                        <tr class="bodyRow left-align">
                            <td style="word-wrap: break-word;" class="centered pointer" id="appName{{ $index }}"><a ng-click="goToAppFromVuln(vuln)">{{ vuln.app.name }}</a></td>
                            <td style="word-wrap: break-word;" class="centered pointer" id="teamName{{ $index }}"><a ng-click="goToTeamFromVuln(vuln)">{{ vuln.team.name }}</a></td>
                            <td class="left-align" >
                                <span style="font-weight: bold;" id="vulnLabelTag{{vuln.id}}{{ $index }}" ng-repeat="vulnTag in vuln.tags" class="pointer badge" ng-class="{'badge-vulnerability-tag': true}" ng-click="goToTag(vulnTag)">{{vulnTag.name}}</span>
                            </td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </td>
        </tr>
        </tbody>
    </table>
</div>