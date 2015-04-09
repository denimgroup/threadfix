var myAppModule = angular.module('threadfix');

myAppModule.controller('CheckLDAPController', function ($scope, $http, tfEncoder) {

  $scope.ok = function (valid) {
    var url = tfEncoder.encode("/configuration/settings/checkLDAP");

    if (valid) {
      $scope.loading = true;

      $http.post(url, $scope.object).
          success(function(data, status, headers, config) {
            $scope.loading = false;

            if (data.success) {
              $scope.successMessage = data.object;
            } else {
              $scope.error = "Failure: " + data.message;
            }
          }).
          error(function(data, status, headers, config) {
            $scope.loading = false;
            $scope.error = "Failure. HTTP status was " + status;
          });
    }
  };

});