var myAppModule = angular.module('threadfix')

myAppModule.controller('VulnTableController', function ($scope, $window, $http, threadfixAPIService) {

    $scope.initialized = false;

    $scope.page = 1;

    $scope.csrfToken = $scope.$parent.csrfToken;

    $scope.goToPage = function() {
        $scope.page = $scope.pageInput;
    }

    var getTableSortBean = function() {
        return {
            page: $scope.page
        }
    }

    var refresh = function() {
        $scope.loading = true;
        $http.post($window.location.pathname + "/table" + $scope.csrfToken,
                getTableSortBean()).
            success(function(data, status, headers, config) {
                $scope.initialized = true;

                if (data.success) {
                    $scope.vulns = data.object;
                } else {
                    $scope.output = "Failure. Message was : " + data.message;
                }

                $scope.loading = false;
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                $scope.loading = false;
            });
    };

    $scope.$watch('csrfToken', refresh);

    $scope.$watch('page', refresh); // TODO look at caching some of this


});