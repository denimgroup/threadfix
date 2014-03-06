var myAppModule = angular.module('threadfix', []);

myAppModule.controller('LoginController', function ($window, $scope) {
    window.onload = function () {
        document.getElementById("username").focus();
    };

    if(top != self) top.location.replace(location);
});
