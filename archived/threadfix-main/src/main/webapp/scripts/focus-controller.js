var myAppModule = angular.module('threadfix');

myAppModule.controller('FocusController', function ($window, $scope, $document) {

    $scope.focus = function() {
        document.getElementById("currentPasswordInput").focus();
    }
});
