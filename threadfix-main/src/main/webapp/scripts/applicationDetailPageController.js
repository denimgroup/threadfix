var myAppModule = angular.module('threadfix')

myAppModule.controller('ApplicationDetailPageController', function ($scope, $window, threadfixAPIService) {

    $scope.onFileSelect = function($files) {
        $scope.$broadcast('fileDragged', $files);
    };


});