var myAppModule = angular.module('threadfix')

myAppModule.controller('ScanMappedFindingTableController', function ($scope, $window, $http, $rootScope, $modal, $log, tfEncoder) {

    $scope.initialized = false;

    $scope.page = 1;

    $scope.$on('rootScopeInitialized', function() {
        return $scope.refresh(true, false);
    });

    $scope.refresh = function(newValue, oldValue) {
        if (newValue !== oldValue) {
            $scope.loading = true;
            $http.post(tfEncoder.encode($scope.$parent.currentUrl + "/table"), getTableSortBean()).
                success(function(data) {

                    if (data.success) {
                        $scope.numPages = data.object.numPages;
                        $scope.page = data.object.page;
                        $scope.numFindings = data.object.numFindings;
                        $scope.numberOfMappedPages = Math.ceil(data.object.numFindings/100);
                        $scope.findingList = data.object.findingList;
                        if ($scope.findingList && $scope.findingList.length) {
                            $scope.findingList.forEach(function(finding) {
                                finding.pageUrl = getFindingUrl(finding);
                            });
                        }
                        $scope.scan = data.object.scan;
                    } else {
                        $scope.output = "Failure. Message was : " + data.message;
                    }

                    $scope.loading = false;
                }).
                error(function(data, status) {
                    $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                    $scope.loading = false;
                });
        }
    };

    $scope.$watch('page', $scope.refresh);

    var getTableSortBean = function() {
        return {
            page: $scope.page
        };
    };

    $scope.goToPage = function(valid) {
        if (valid) {
            $scope.page = $scope.pageInput;
        }
    };

    var getFindingUrl = function(finding) {
        return tfEncoder.encode($scope.$parent.currentUrl + "/findings/" + finding.id);
    };

});