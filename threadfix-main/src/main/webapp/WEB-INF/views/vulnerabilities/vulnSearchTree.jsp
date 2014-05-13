<div ng-show="vulnTree" class="vuln-tree">
    <h3>Results</h3>

    <div ng-hide="vulnTree && vulnTree.length > 0">
        No results found.
    </div>

    <table>
        <tbody ng-repeat="category in vulnTree" ng-show="category.total > 0">
            <tr>
                <td>
                    <span ng-hide="category.expanded" ng-click="category.expanded = true" class="icon icon-plus-sign"></span>
                    <span ng-show="category.expanded" ng-click="category.expanded = false" class="icon icon-minus-sign"></span>
                </td>
                <td>
                    {{ category.name }}
                </td>
                <td>
                    <span ng-style="badgeWidth" class="badge" ng-class="{
                                            'badge-important': category.intValue === 5,
                                            'badge-warning': category.intValue === 4,
                                            'badge-success': category.intValue === 3,
                                            'badge-info': category.intValue === 2 || element.intValue === 1
                                            }">
                        {{ category.total }}
                    </span>
                </td>
            </tr>
            <tr ng-repeat-start="element in category.entries" ng-show="category.expanded">
                <td></td>
                <td>
                    <span ng-hide="element.expanded" ng-click="expandAndRetrieveTable(element)" class="icon icon-plus-sign"></span>
                    <span ng-show="element.expanded" ng-click="element.expanded = false" class="icon icon-minus-sign"></span>
                </td>
                <td>
                    <span ng-style="badgeWidth" class="badge" ng-class="{
                                    'badge-important': element.intValue === 5,
                                    'badge-warning': element.intValue === 4,
                                    'badge-success': element.intValue === 3,
                                    'badge-info': element.intValue === 2 || element.intValue === 1
                                    }">
                        {{ element.numResults }}
                    </span>
                </td>
                <td>
                    {{ element.genericVulnerability.name | shortCweNames }}
                </td>
            </tr>
            <tr ng-show="element.expanded" ng-repeat-end>
                <td></td>
                <td colspan="3">
                    <div style="height:34px;padding-top:5px;">
                        <span>
                            <ul style="width:190px; float:left" class="nav nav-pills">
                                <li ng-class="{ active: element.numberToShow === 10 }"> <a ng-click="updateElementTable(element, 10, 1)">10</a></li>
                                <li ng-class="{ active: element.numberToShow === 25 }"> <a ng-click="updateElementTable(element, 25, 1)">25</a></li>
                                <li ng-class="{ active: element.numberToShow === 50 }"> <a ng-click="updateElementTable(element, 50, 1)">50</a></li>
                                <li ng-class="{ active: element.numberToShow === 100 }"><a ng-click="updateElementTable(element, 100, 1)">100</a></li>
                            </ul>
                        </span>
                        <span style="margin:2px;float:left;" ng-form="form" class="pagination" ng-show="element.totalVulns > element.numberToShow">
                            <pagination class="no-margin"
                                        total-items="element.totalVulns / element.numberToShow * 10"
                                        max-size="5"
                                        ng-model="element.page"
                                        page="element.page"
                                        direction-links="false"
                                        boundary-links="true"
                                        ng-click="updateElementTable(element, element.numberToShow, element.page)"></pagination>
                        </span>
                    </div>
                    <div ng-repeat="vuln in element.vulns">
                        <hr>
                        {{ vuln.path }}
                        <br>
                        {{ vuln.parameter }}
                    </div>
                </td>
            </tr>

        </tbody>
    </table>

</div>