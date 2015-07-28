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
        <tbody ng-repeat="category in vulnTree" >
            <tr>
                <td>
                    <span id="expand{{ category.name }}" ng-hide="category.expanded" ng-click="toggleVulnCategory(category, true)" class="icon icon-plus-sign"></span>
                    <span id="collapse{{ category.name }}" ng-show="category.expanded" ng-click="toggleVulnCategory(category, false)" class="icon icon-minus-sign"></span>
                </td>
                <td colspan="2">
                    <span id="totalBadge{{ category.name }}" ng-style="badgeWidth" class="badge" ng-class="{
                                            'badge-critical': category.intValue === 5 && category.total !== 0,
                                            'badge-high': category.intValue === 4 && category.total !== 0,
                                            'badge-medium': category.intValue === 3 && category.total !== 0,
                                            'badge-low': category.intValue === 2 && category.total !== 0,
                                            'badge-info': category.intValue === 1 && category.total !== 0,
                                            'badge-inform': category.total === 0
                                            }">
                        {{ category.total }}
                    </span>
                    {{ category.name }}
                </td>
                <td></td>
            </tr>
            <tr ng-repeat-start="element in category.entries" ng-show="category.expanded">
                <td></td>
                <td colspan="3">
                    <span id="expandVuln{{ category.name }}{{ element.genericVulnerability.displayId }}" ng-hide="element.expanded" ng-click="expandAndRetrieveTable(element)" class="icon icon-plus-sign"></span>
                    <span id="collapseVuln{{ category.name }}{{ element.genericVulnerability.displayId }}" ng-show="element.expanded" ng-click="element.expanded = false" class="icon icon-minus-sign"></span>
                    <span id="totalBadge{{ category.name }}{{ element.genericVulnerability.displayId }}" ng-style="badgeWidth" class="badge" ng-class="{
                                        'badge-critical': category.intValue === 5,
                                        'badge-high': category.intValue === 4,
                                        'badge-medium': category.intValue === 3,
                                        'badge-low': category.intValue === 2,
                                        'badge-info': category.intValue === 1
                                    }">
                        {{ element.numResults }}
                    </span>
                    <span id="cweName{{ category.name }}{{ element.genericVulnerability.displayId }}">
                        <span ng-if="element.preText"> {{ element.preText }}:  </span> {{ element.genericVulnerability.name | shortCweNames }}</span>
                </td>
            </tr>
            <tr ng-if="category.expanded && element.expanded" ng-repeat-end>
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
        <tbody ng-repeat="category in exportVulnTree" >
        <tr>
            <td colspan="2" ng-class="{
                                            'text-critical': category.intValue === 5 && category.total !== 0,
                                            'text-high': category.intValue === 4 && category.total !== 0,
                                            'text-medium': category.intValue === 3 && category.total !== 0,
                                            'text-low': category.intValue === 2 && category.total !== 0,
                                            'text-info': category.intValue === 1 && category.total !== 0,
                                            'text-inform': category.total === 0
                                            }">
                <p><b> {{ category.total }} {{ category.name }} </b></p>
            </td>
            <td></td>
        </tr>
        <tr ng-repeat-start="element in category.entries">
            <td colspan="3">
                <p><b>{{ element.numResults }} {{ category.name }} {{ element.genericVulnerability.name | shortCweNames }}</b></p>
            </td>
        </tr>
        <tr ng-repeat-end>
            <td colspan="4" class="vuln-tree-vuln-list">
                <div class="accordion-group">
                    <%@ include file="vulnTreeVulnRowsPdf.jsp" %>
                </div>
            </td>
        </tr>
        </tbody>
    </table>


</div>
