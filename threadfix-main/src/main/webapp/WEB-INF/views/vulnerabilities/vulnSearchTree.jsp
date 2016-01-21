<div class="vuln-tree" ng-controller="VulnSearchTreeController">
    <h3 ng-hide="hideTitle">
        <span style="float:left">
            Results
        </span><br style="clear:both;" />
        <span class="spinner-div">
            <span id="vulnTreeLoadingSpinner" ng-show="loadingTree || !vulnTree" class="spinner dark"></span>
        </span>
    </h3>
    <div id="noResultsFound" ng-if="vulnTree && vulnTree.length == 0">
        No results found.
    </div>
    <a id="toggleVulnTree" class="btn" ng-click="toggleVulnTree()" ng-show="vulnTree && vulnTree.length > 0" style="margin: -9px 0 8px 0;">
        {{ vulnTree.expanded ? 'Collapse' : 'Expand' }} All
    </a>
    <table ng-show="vulnTree">
        <tbody ng-repeat="primaryPivot in vulnTree" >
            <tr>
                <td>
                    <span id="expand{{ primaryPivot.name }}" ng-hide="primaryPivot.expanded" ng-click="toggleVulnPivot(primaryPivot, true)" class="icon icon-plus-sign"></span>
                    <span id="collapse{{ primaryPivot.name }}" ng-show="primaryPivot.expanded" ng-click="toggleVulnPivot(primaryPivot, false)" class="icon icon-minus-sign"></span>
                </td>
                <td colspan="2">
                    <span id="totalBadge{{ primaryPivot.name }}" ng-style="badgeWidth" class="badge" ng-class="{
                                            'badge-critical': primaryPivot.intValue === 5 && primaryPivot.total !== 0,
                                            'badge-high': primaryPivot.intValue === 4 && primaryPivot.total !== 0,
                                            'badge-medium': primaryPivot.intValue === 3 && primaryPivot.total !== 0,
                                            'badge-low': primaryPivot.intValue === 2 && primaryPivot.total !== 0,
                                            'badge-info': primaryPivot.intValue === 1 && primaryPivot.total !== 0,
                                            'badge-inform': primaryPivot.total === 0
                                            }">
                        {{ primaryPivot.total }}
                    </span>
                    <span ng-show="primaryPivot.name">{{ primaryPivot.name | shortCweNames }}</span>
                    <span ng-hide="primaryPivot.name">None</span>
                </td>
                <td></td>
            </tr>
            <tr ng-repeat-start="element in primaryPivot.entries" ng-show="primaryPivot.expanded && element.numResults > 0">
                <td></td>
                <td colspan="3">
                    <span id="expandVuln{{ primaryPivot.name }}" ng-hide="element.expanded" ng-click="expandAndRetrieveTable(element)" class="icon icon-plus-sign"></span>
                    <span id="collapseVuln{{ primaryPivot.name }}" ng-show="element.expanded" ng-click="element.expanded = false" class="icon icon-minus-sign"></span>
                    <span id="totalBadgeVuln{{ primaryPivot.name }}" ng-style="badgeWidth" class="badge" ng-class="{
                                        'badge-critical': element.intValue === 5,
                                        'badge-high': element.intValue === 4,
                                        'badge-medium': element.intValue === 3,
                                        'badge-low': element.intValue === 2,
                                        'badge-info': element.intValue === 1,
                                        'badge-inform': element.total === 0
                                    }">
                        {{ element.numResults }}
                    </span>
                    <span id="secondaryPivotName{{ primaryPivot.name}}">
                        <span ng-if="element.preText"> {{ element.preText }}:  </span>
                        <span ng-show="element.secondaryPivotName">{{ element.secondaryPivotName | shortCweNames }}</span>
                        <span ng-hide="element.secondaryPivotName">None</span>
                    </span>
                </td>
            </tr>
            <tr ng-if="primaryPivot.expanded && element.expanded" ng-repeat-end>
                <td></td>
                <td colspan="4" class="vuln-tree-vuln-list">
                    <div class="accordion-group">
                        <%@ include file="vulnTreeGroupHeader.jsp" %>
                        <%@ include file="vulnTreeVulnRows.jsp" %>
                    </div>
                </td>
            </tr>
        </tbody>
    </table>


    <!-- For PDF export -->
    <br>
    <table ng-if="exportingPDF" id="pointInTimeTablePdf" class="pdf-data">
        <tbody ng-repeat="primaryPivot in vulnTree" >
        <tr>
            <td colspan="2" ng-class="{
                                            'text-critical': primaryPivot.intValue === 5 && primaryPivot.total !== 0,
                                            'text-high': primaryPivot.intValue === 4 && primaryPivot.total !== 0,
                                            'text-medium': primaryPivot.intValue === 3 && primaryPivot.total !== 0,
                                            'text-low': primaryPivot.intValue === 2 && primaryPivot.total !== 0,
                                            'text-info': primaryPivot.intValue === 1 && primaryPivot.total !== 0,
                                            'text-inform': primaryPivot.total === 0
                                            }">
                <p><b> {{ primaryPivot.total }} {{ primaryPivot.name }} </b></p>
            </td>
            <td></td>
        </tr>
        <tr ng-repeat-start="element in primaryPivot.entries">
            <td colspan="3">
                <p><b>{{ element.numResults }} {{ primaryPivotprim.name }} {{ element.genericVulnerability.name | shortCweNames }}</b></p>
            </td>
        </tr>
        <tr ng-repeat-end>
            <td colspan="4" class="vuln-tree-vuln-list"/>
        </tr>
        </tbody>
    </table>


</div>
