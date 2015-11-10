angular.module('inputDropdown', []).directive('inputDropdown', [function() {
  var templateString =
  '<div class="input-dropdown">' +
    '<input type="text"' +
           'name="{{inputName}}"' +
           'placeholder="{{inputPlaceholder}}"' +
           'ng-model="inputValue"' +
           'ng-required="inputRequired"' +
           'ng-change="inputChange()"' +
           'ng-focus="inputFocus()"' +
           'ng-blur="inputBlur($event)"' +
           'input-dropdown-validator>' +
     '<ul ng-show="dropdownVisible">' +
      '<li ng-repeat="item in dropdownItems"' +
          'ng-click="selectItem(item)"' +
          'ng-mouseenter="setActive($index)"' +
          'ng-mousedown="dropdownPressed()"' +
          'ng-class="{\'active\': activeItemIndex === $index}"' +
          '>' +
        '<span ng-if="item.readableName">{{item.readableName}}</span>' +
        '<span ng-if="!item.readableName">{{item}}</span>' +
      '</li>' +
    '</ul>' +
  '</div>';

  return {
    restrict: 'E',
    scope: {
      defaultDropdownItems: '=',
      selectedItem: '=',
      inputRequired: '=',
      inputName: '@',
      inputPlaceholder: '@',
      inputValueInit: '=',
      filterListMethod: '&',
      itemSelectedMethod: '&'
    },
    template: templateString,
    controller: function($scope) {
      this.getSelectedItem = function() {
        return $scope.selectedItem;
      };
      this.isRequired = function() {
        return $scope.inputRequired;
      };
    },
    link: function(scope, element) {
      var pressedDropdown = false;
      var inputScope = element.find('input').isolateScope();

      scope.activeItemIndex = 0;
      scope.inputValue = scope.inputValueInit;
      scope.dropdownVisible = false;
      scope.dropdownItems = scope.defaultDropdownItems || [];

      scope.$watch('dropdownItems', function(newValue, oldValue) {
        if (!angular.equals(newValue, oldValue)) {
          // If new dropdownItems were retrieved, reset active item
          scope.setActive(0);
        }
      });

      scope.$watch('defaultDropdownItems', function(newValue, oldValue) {
        if (!angular.equals(newValue, oldValue)) {
          // If new dropdownItems were retrieved, reset active item
          scope.dropdownItems = scope.defaultDropdownItems || [];
          scope.setActive(0);
        }
      });

      scope.$watch('selectedItem', function(newValue, oldValue) {
        inputScope.updateInputValidity();

        if (!angular.equals(newValue, oldValue)) {
          if (newValue) {
            // Update value in input field to match readableName of selected item
            if (typeof newValue === 'string') {
              scope.inputValue = newValue;
            }
            else {
              scope.inputValue = newValue.readableName;
            }
          }
          else {
            // Uncomment to clear input field when editing it after making a selection
            // scope.inputValue = '';
          }
        }
      });

      scope.setActive = function(itemIndex) {
        scope.activeItemIndex = itemIndex;
      };

      scope.inputChange = function() {
        scope.selectedItem = null;
        showDropdown();

        if (!scope.inputValue) {
          scope.dropdownItems = scope.defaultDropdownItems || [];
          return;
        }

        if (scope.filterListMethod) {
          var promise = scope.filterListMethod({userInput: scope.inputValue});
          if (promise) {
            promise.then(function(dropdownItems) {
              scope.dropdownItems = dropdownItems;
            });
          }
        }
      };

      scope.inputFocus = function() {
        scope.setActive(0);
        showDropdown();
      };

      scope.inputBlur = function(event) {
        if (pressedDropdown) {
          // Blur event is triggered before click event, which means a click on a dropdown item wont be triggered if we hide the dropdown list here.
          pressedDropdown = false;
          return;
        }
        hideDropdown();
      };

      scope.dropdownPressed = function() {
        pressedDropdown = true;
      }

      scope.selectItem = function(item) {
        scope.selectedItem = item;
        hideDropdown();
        scope.dropdownItems = [item];

        if (scope.itemSelectedMethod) {
          scope.itemSelectedMethod({item: item});
        }
      };

      var showDropdown = function () {
        scope.dropdownVisible = true;
      };
      var hideDropdown = function() {
        scope.dropdownVisible = false;
      }

      var selectPreviousItem = function() {
        var prevIndex = scope.activeItemIndex - 1;
        if (prevIndex >= 0) {
          scope.setActive(prevIndex);
        }
      };

      var selectNextItem = function() {
        var nextIndex = scope.activeItemIndex + 1;
        if (nextIndex < scope.dropdownItems.length) {
          scope.setActive(nextIndex);
        }
      };

      var selectActiveItem = function()  {
        if (scope.activeItemIndex >= 0 && scope.activeItemIndex < scope.dropdownItems.length) {
          scope.selectItem(scope.dropdownItems[scope.activeItemIndex]);
        }
      };

      element.bind("keydown keypress", function (event) {
        switch (event.which) {
          case 38: //up
            scope.$apply(selectPreviousItem);
            break;
          case 40: //down
            scope.$apply(selectNextItem);
            break;
          case 13: // return
            if (scope.dropdownVisible && scope.dropdownItems && scope.dropdownItems.length > 0) {
              // only preventDefault when there is a list so that we can submit form with return key after a selection is made
              event.preventDefault();
              scope.$apply(selectActiveItem);
            }
            break;
        }
      });
    }
  }
}]);

angular.module('inputDropdown').directive('inputDropdownValidator', function() {
  return {
    require: ['^inputDropdown', 'ngModel'],
    restrict: 'A',
    scope: {},
    link: function(scope, element, attrs, ctrls) {
      var inputDropdownCtrl = ctrls[0];
      var ngModelCtrl = ctrls[1];
      var validatorName = 'itemSelectedValid';

      scope.updateInputValidity = function() {
        var selection = inputDropdownCtrl.getSelectedItem();
        if (selection || !inputDropdownCtrl.isRequired()) {
          ngModelCtrl.$setValidity(validatorName, true);
        }
        else {
          ngModelCtrl.$setValidity(validatorName, false);
        }
      };
    }
  };
});
