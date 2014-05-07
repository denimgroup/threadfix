var module = angular.module('threadfix');

module.controller('VulnSearchController', function($scope, $http, tfEncoder) {
    $scope.parameters = {
        teams: [{ name: '' }]
    };

    $scope.submit = function() {

    }

    $scope.addTeam = function() {
        $scope.parameters.teams.push({ name: '' })
    }

    $scope.removeTeam = function(index) {
        $scope.parameters.teams.splice(index, 1);
    }


});
