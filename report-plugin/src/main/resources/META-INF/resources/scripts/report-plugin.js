var threadfixModule = angular.module('threadfix');

threadfixModule.controller('ReportPluginController', function($scope, $http, $modal, $rootScope, $log, tfEncoder) {

    $scope.$on('rootScopeInitialized', function() {
        $scope.heading = 'Test Plugin Name';
        $scope.body = 'Report Plugin Module goes here';
    });

});