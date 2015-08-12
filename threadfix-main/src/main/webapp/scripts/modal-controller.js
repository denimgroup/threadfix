var myAppModule = angular.module('threadfix');

myAppModule.controller('ModalController', function ($scope, $modalInstance, data) {

    $scope.data = data;

    $scope.cancel = function () {
        $modalInstance.dismiss('cancel');
    };
});