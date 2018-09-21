var module = angular.module('threadfix')

module.controller('WafDetailPageController', function($scope, $window, $http, $modal, $log, tfEncoder){

    $scope.wafId  = $window.location.pathname.match(/([0-9]+)$/)[0];
    $scope.base = $window.location.pathname;

    $scope.$on('rootScopeInitialized', function() {
        refresh();
        $scope.loading = false;
    });

    var refresh = function() {
        $http.get(tfEncoder.encode('/wafs/' + $scope.wafId + '/getRules')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.waf = data.object.waf;
                    $scope.rulesText = data.object.rulesText;

                    $scope.wafDirective = data.object.lastDirective.directive;

                    if (!$scope.wafApplicationId)
                        $scope.wafApplicationId = -1;


                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve waf rules. HTTP status was " + status;
            });
    }

    $scope.goToRule = function(wafRule) {
        window.location.href = tfEncoder.encode("/wafs/" + $scope.wafId + "/rule/" + wafRule.id);
    }

    $scope.generateRules = function() {

        $scope.wafApplicationId = this.wafApplicationId;
        $scope.wafDirective = this.wafDirective;

        $http.post(tfEncoder.encode('/wafs/' + $scope.wafId + '/generateRules/' +  $scope.wafApplicationId + '/' +  $scope.wafDirective)).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.waf = data.object.waf;
                    $scope.rulesText = data.object.rulesText;

                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve waf list. HTTP status was " + status;
            });
    }

});