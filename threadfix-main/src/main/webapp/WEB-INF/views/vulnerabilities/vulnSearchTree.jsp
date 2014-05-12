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
                    <div class="pagination">
                        <div ng-form="form" class="pagination" ng-show="totalVulns > numberVulnerabilities">
                            <pagination class="no-margin" total-items="totalVulns / numResults" max-size="5" page="page"></pagination>

                            <input id="pageInput" name="pageInput" ng-enter="goToPage(form.$valid)" style="width:50px" type="number" ng-model="pageInput" max="{{ element.max }}" min="1"/>
                            <span class="errors" ng-show="form.pageInput.$dirty && form.pageInput.$error.min || form.pageInput.$error.max">Input number from 1 to {{ max }}</span>
                            <span class="errors" ng-show="form.pageInput.$dirty && form.pageInput.$error.number">Not a valid number</span>
                        </div>
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