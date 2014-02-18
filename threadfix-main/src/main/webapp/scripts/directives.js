var threadfixModule = angular.module('threadfix')

// For image tags and stuff
threadfixModule.directive('bindHtmlUnsafe', function( $compile ) {
    return function( $scope, $element, $attrs ) {

        var compile = function( newHTML ) { // Create re-useable compile function

            newHTML = $compile(newHTML)($scope); // Compile html
            $element.html('').append(newHTML);
        };

        var htmlName = $attrs.bindHtmlUnsafe; // Get the name of the variable
        // Where the HTML is stored

        $scope.$watch(htmlName, function( newHTML ) { // Watch for changes to
            // the HTML
            if(!newHTML) return;
            compile(newHTML);   // Compile it
        });

    };
});