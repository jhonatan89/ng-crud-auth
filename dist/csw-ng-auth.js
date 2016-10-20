(function (ng) {

    var mod = ng.module('authModule', [
        'ui.router',
        'checklist-model',
        'ngMessages',
        'ui.bootstrap',
        'stormpath',
        'stormpath.templates'
    ]);

    mod.config(['$stateProvider', 'authServiceProvider', function ($stateProvider, auth) {
            var authConfig = auth.getValues();
            $stateProvider
                    .state(authConfig.loginState, {
                        url: authConfig.loginState,
                        templateUrl: 'src/templates/login.html',
                        controller: 'loginCtrl',
                        controllerAs: 'authCtrl'
                    })
                    .state(authConfig.registerState, {
                        url: authConfig.registerState,
                        templateUrl: 'src/templates/register.html',
                        controller: 'registerCtrl',
                        controllerAs: 'authCtrl'
                    })
                    .state(authConfig.forgotPassState, {
                        url: authConfig.forgotPassState,
                        templateUrl: 'src/templates/forgotPass.html',
                        controller: 'forgotCtrl',
                        controllerAs: 'authCtrl'
                    })
                    .state(authConfig.forbiddenState, {
                        url: authConfig.forbiddenState,
                        templateUrl: 'src/templates/forbidden.html',
                        controller: 'forbiddenCtrl'
                    });
        }]);

    mod.config(['$httpProvider', function ($httpProvider) {
            $httpProvider.interceptors.push(['$q', '$log', '$injector', function ($q, $log, $injector) {
                    return {
                        request: function (config) {
                            config.withCredentials = true;
                            return config;
                        }
                    };
                }]);
        }]);
})(window.angular);



(function (ng) {

    var mod = ng.module('authModule');

    mod.provider('authService', function () {

        //Default
        var values = {
            apiUrl: 'api/users/',
            loginState: 'login',
            logoutRedirectState: 'login',
            registerState: 'register',
            forgotPassState: 'forgot',
            successState: 'home',
            forbiddenState: 'forbidden',
            loginURL: 'login',
            registerURL: 'register',
            logoutURL: 'logout',
            forgotPassURL: 'forgot',
            meURL: 'me'
        };

        //Default Roles
        var roles = {};

        this.setValues = function (newValues) {
            values = ng.extend(values, newValues);
        };

        this.getValues = function () {
            return values;
        };

        this.getRoles = function(){
            return roles;
        };

        this.setRoles = function(newRoles){
            roles = newRoles;
        };

        this.$get = ['$state', '$http','$rootScope','$log', function ($state, $http, $rootScope, $log) {
            return {
                getRoles: function(){
                    return roles;
                },
                login: function (user) {
                    return $http.post(values.apiUrl+values.loginURL, user).then(function (response) {
                        $rootScope.$broadcast('logged-in', response.data);
                        $log.debug("user", response.data);
                        $state.go(values.successState);
                    });
                },
                getConf: function () {
                    return values;
                },
                logout: function () {
                    return $http.get(values.apiUrl+values.logoutURL).then(function () {
                        $rootScope.$broadcast('logged-out');
                        $state.go(values.logoutRedirectState);
                    });
                },
                register: function (user) {
                    return $http.post(values.apiUrl+values.registerURL, user).then(function (data) {
                        $state.go(values.loginState);
                    });
                },
                forgotPass: function (user) {
                    return $http.post(values.apiUrl+values.forgotPassURL, user).then(function (data) {
                        $state.go(values.loginState);
                    });
                },
                goToRegister: function () {
                    $state.go(values.registerState);
                },
                goToLogin: function () {
                    $state.go(values.loginState);
                },
                goToForgotPass: function(){
                    $state.go(values.forgotPassState);
                },
                goToSuccess: function () {
                    $state.go(values.successState);
                },
                goToForbidden: function(){
                    $state.go(values.forbiddenState);
                },
                userAuthenticated: function(){
                    return $http.get(values.apiUrl + values.meURL);
                }
            };
        }];
    });
})(window.angular);

(function (ng) {

    var mod = ng.module('authModule');

    mod.controller('forbiddenCtrl', ['$scope', 'authService', function ($scope, authSvc) {
        $scope.goToSuccess = function () {
            authSvc.goToSuccess();
        };
    }]);

})(window.angular);



(function (ng) {

    var mod = ng.module('authModule');

    mod.controller('forgotCtrl', ['$scope', '$cookies', 'authService', '$log', function ($scope, $cookies, authSvc, $log) {
        $scope.alerts = [];
        authSvc.userAuthenticated().then(function (data) {
            $scope.currentUser = data.data;
            if ($scope.currentUser !== "" && !$scope.menuitems) {
                $scope.setMenu($scope.currentUser);
            }
        });

        //Alerts
        this.closeAlert = function (index) {
            $scope.alerts.splice(index, 1);
        };

        function showMessage(msg, type) {
            var types = ["info", "danger", "warning", "success"];
            if (types.some(function (rc) {
                    return type === rc;
                })) {
                $scope.alerts.push({ type: type, msg: msg });
            }
        }

        this.showError = function (msg) {
            showMessage(msg, "danger");
        };

        this.showSuccess = function (msg) {
            showMessage(msg, "success");
        };

        this.forgotPass = function (user) {
            var self = this;
            if (user) {
                $scope.loading = true;
                authSvc.forgotPass(user).then(function () {}, function (data) {
                        self.showError(data.data.substring(66));
                    }
                ).finally(function () {
                    $scope.loading = false;
                });
            }
        };

        this.goBack = function () {
            authSvc.goToLogin();
        };
    }]);

})(window.angular);
/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
(function (ng) {

    var mod = ng.module('authModule');

    mod.directive('loginButton', [function () {
            return {
                scope: {},
                restrict: 'E',
                templateUrl: 'src/templates/button.html',
                controller: ['$scope', 'authService', function ($scope, authSvc) {
                        $scope.roles = authSvc.getRoles();
                        authSvc.userAuthenticated().then(function (resp) {
                            $scope.currentUser = resp.data;
                            if ($scope.currentUser !== "" && !$scope.menuitems) {
                                $scope.setMenu($scope.currentUser);
                            }
                        });
                        $scope.$on('$authenticated', function (events, resp) {
                            $scope.currentUser = resp.data;
                            $scope.setMenu($scope.currentUser);
                        });

                        $scope.setMenu = function (user) {
                            $scope.menuitems = [];
                            for (var rol in $scope.roles) {
                                if (user.roles.indexOf(rol) !== -1) {
                                    for (var menu in $scope.roles[rol]) {
                                        if ($scope.menuitems.indexOf($scope.roles[rol][menu]) === -1) {
                                            $scope.menuitems.push($scope.roles[rol][menu]);
                                        }
                                    }
                                }
                            }
                        };

                        $scope.isAuthenticated = function () {
                            return !!$scope.currentUser;
                        };

                        $scope.logout = function () {
                            return authSvc.logout();
                        };

                        $scope.goToLogin = function () {
                            authSvc.goToLogin();
                        };
                    }]
            };
        }]);
})(window.angular);


/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
(function (ng) {

    var mod = ng.module('authModule');

    mod.controller('loginCtrl', ['$scope', '$cookies', 'authService', '$log', function ($scope, $cookies, authSvc, $log) {
            authSvc.userAuthenticated().then(function (data) {
                $scope.currentUser = data.data;
                if ($scope.currentUser !== "" && !$scope.menuitems) {
                    $scope.setMenu($scope.currentUser);
                }
            });
            $scope.loading = false;

            //Alerts
            $scope.alerts = [];
            this.closeAlert = function (index) {
                $scope.alerts.splice(index, 1);
            };

            function showMessage(msg, type) {
                var types = ["info", "danger", "warning", "success"];
                if (types.some(function (rc) {
                    return type === rc;
                })) {
                    $scope.alerts.push({type: type, msg: msg});
                }
            }

            this.showError = function (msg) {
                showMessage(msg, "danger");
            };

            this.showSuccess = function (msg) {
                showMessage(msg, "success");
            };


            this.login = function (user) {
                var self = this;
                if (user && user.userName && user.password) {
                    $scope.loading = true;
                    authSvc.login(user).then(function (data) {
                    }, function (data) {
                        self.showError(data.data);
                        $log.error("Error", data);
                    }).finally(function () {
                        $scope.loading = false;
                    });
                }
            };

            this.registration = function () {
                authSvc.goToRegister();
            };

            this.goToForgotPass = function () {
                authSvc.goToForgotPass();
            };
        }]);

})(window.angular);


(function (ng) {

    var mod = ng.module('authModule');

    mod.controller('registerCtrl', ['$scope', 'authService', '$log', function ($scope, authSvc, $log) {

            //Alerts
            $scope.alerts = [];
            $scope.closeAlert = function (index) {
                $scope.alerts.splice(index, 1);
            };

            $scope.roles = authSvc.getRoles();
            authSvc.userAuthenticated().then(function (data) {
                $scope.currentUser = data.data;
                if ($scope.currentUser !== "" && !$scope.menuitems) {
                    $scope.setMenu($scope.currentUser);
                }
            });
            $scope.loading = false;
            $scope.$on('logged-in', function (events, user) {
                $scope.currentUser = user;
                $scope.setMenu($scope.currentUser);
            });

            $scope.setMenu = function (user) {
                $scope.menuitems = [];
                for (var rol in $scope.roles) {
                    if (user.roles.indexOf(rol) !== -1) {
                        for (var menu in $scope.roles[rol]) {
                            if ($scope.menuitems.indexOf($scope.roles[rol][menu]) === -1) {
                                $scope.menuitems.push($scope.roles[rol][menu]);
                            }
                        }
                    }
                }
            };

            function showMessage(msg, type) {
                var types = ["info", "danger", "warning", "success"];
                if (types.some(function (rc) {
                    return type === rc;
                })) {
                    $scope.alerts.push({type: type, msg: msg});
                }
            }

            this.showError = function (msg) {
                showMessage(msg, "danger");
            };

            this.showSuccess = function (msg) {
                showMessage(msg, "success");
            };

            this.register = function (newUser) {
                var self = this;
                $scope.loading = true;
                delete newUser.confirmpassword;
                authSvc.register(newUser).then(function (data) {
                    self.showSuccess("User registered successfully");
                }, function (data) {
                    self.showError(data.data.substring(65));
                }).finally(function () {
                    $scope.loading = false;
                });
            };

            $scope.isCheckRequired = function (newUser) {
                return !newUser;
            };
            this.goBack = function () {
                authSvc.goToLogin();
            };
        }]);

})(window.angular);

angular.module('authModule').run(['$templateCache', function($templateCache) {
  'use strict';

  $templateCache.put('src/forbidden/forbidden.html',
    "<div class=\"jumbotron\"><h1>Forbidden!!</h1><p>You don't have permissions for this resource!!</p><p><a class=\"btn btn-primary btn-lg\" ng-click=\"goToSuccess()\" role=\"button\">Back</a></p></div>"
  );


  $templateCache.put('src/forgot/forgotPass.html',
    "<div><div class=\"col-md-5 col-md-offset-4\"><div class=\"col-md-12\"><alert ng-repeat=\"alert in alerts\" type=\"{{alert.type}}\" close=\"authCtrl.closeAlert($index)\">{{alert.msg}}</alert><div class=\"panel panel-default\"><div class=\"panel-heading\"><h2 class=\"panel-title\">Password assistance</h2></div><div class=\"panel-body\"><div ng-messages=\"forgotPassform.email.$error\" ng-show=\"(forgotPassform.$error.required || forgotPassform.email.$invalid) && forgotPassform.email.$touched\"><div ng-message=\"required\"><alert type=\"danger\" close=\"\">Please, Fill the required field!</alert></div><div ng-message=\"email\"><alert type=\"danger\" close=\"\">Your email address is invalid!</alert></div></div><p>Enter the email address associated with your account, then click <strong>Send Email</strong>. We'll send you a link to a page where you can easily create a new password.</p><form name=\"forgotPassform\" accept-charset=\"UTF-8\" role=\"form\" ng-submit=\"authCtrl.forgotPass(user)\"><div class=\"form-group\" ng-class=\"{'has-success': forgotPassform.email.$valid, 'has-error': forgotPassform.email.$invalid}\"><input class=\"form-control\" required ng-model=\"user.email\" placeholder=\"Email\" name=\"email\" type=\"email\"></div><input class=\"btn btn-lg btn-success btn-block\" type=\"submit\" value=\"Send Email\"></form><button class=\"btn btn-lg btn-default btn-block\" ng-click=\"authCtrl.goBack()\" type=\"button\">Go Back</button><div class=\"spinner text-center\" ng-show=\"loading\"><img src=\"http://www.lectulandia.com/wp-content/themes/ubook/images/spinner.gif\" alt=\"Loading\" style=\"width:48px;height:48px\"></div></div></div></div></div></div>"
  );


  $templateCache.put('src/login/button.html',
    "<button ng-hide=\"isAuthenticated()\" type=\"button\" class=\"btn btn-default navbar-btn\" ng-click=\"goToLogin()\"><span class=\"glyphicon glyphicon-user\" aria-hidden=\"true\"></span> Login</button><div ng-show=\"isAuthenticated()\" class=\"btn-group\"><button type=\"button\" class=\"btn btn-default dropdown-toggle navbar-btn\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"false\">{{currentUser.userName}} <span class=\"caret\"></span></button><ul class=\"dropdown-menu\"><li ng-repeat=\"menuitem in menuitems\"><a ui-sref=\"{{menuitem.state}}\"><span class=\"glyphicon glyphicon-{{menuitem.icon}}\" aria-hidden=\"true\"></span> {{menuitem.label}}</a></li><li><a href ng-click=\"logout()\"><span class=\"glyphicon glyphicon-log-out\" aria-hidden=\"true\"></span> Logout</a></li></ul></div>"
  );


  $templateCache.put('src/login/login.html',
    "<div><div class=\"col-md-5 col-md-offset-4\"><alert ng-repeat=\"alert in alerts\" type=\"{{alert.type}}\" close=\"authCtrl.closeAlert($index)\">{{alert.msg}}</alert><div class=\"col-md-12\"><div class=\"panel panel-default\"><div class=\"panel-heading\"><h3 class=\"panel-title\">Please Login</h3></div><div class=\"panel-body\"><form name=\"loginform\" accept-charset=\"UTF-8\" role=\"form\" ng-submit=\"authCtrl.login(user)\"><div class=\"form-group\"><input class=\"form-control\" required ng-model=\"user.userName\" placeholder=\"Username or Email\" name=\"username\" type=\"text\"></div><div class=\"form-group\"><div class=\"text-right\"><a align=\"right\" ng-click=\"authCtrl.goToForgotPass()\">Forgot your password?</a></div><input class=\"form-control\" required ng-model=\"user.password\" placeholder=\"Password\" name=\"password\" type=\"password\"></div><div class=\"checkbox\"><label><input name=\"rememberMe\" type=\"checkbox\" ng-model=\"user.rememberMe\" value=\"false\"> Remember Me</label></div><input class=\"btn btn-lg btn-success btn-block\" type=\"submit\" value=\"Login\"></form><button class=\"btn btn-lg btn-default btn-block\" ng-click=\"authCtrl.registration()\">Create an account</button><div class=\"spinner text-center\" ng-show=\"loading\"><img src=\"http://www.lectulandia.com/wp-content/themes/ubook/images/spinner.gif\" alt=\"Loading\" style=\"width:48px;height:48px\"></div></div></div></div></div></div>"
  );


  $templateCache.put('src/register/register.html',
    "<div><div class=\"col-md-5 col-md-offset-4\"><alert ng-repeat=\"alert in alerts\" type=\"{{alert.type}}\" close=\"authCtrl.closeAlert($index)\">{{alert.msg}}</alert><div class=\"panel panel-default\"><div class=\"panel-heading\"><h3 class=\"panel-title\">Please Register</h3></div><div class=\"panel-body\"><div ng-messages=\"loginform.$error\" ng-show=\"(loginform.$error.required || loginform.email.$invalid || loginform.confirmpassword.$error || loginform.$error.minlength ) && loginform.username.$touched\"><div ng-message=\"required\"><alert type=\"danger\" close=\"\">Please, Fill the required fields!</alert></div><div ng-message=\"minlength\"><alert type=\"danger\" close=\"\">Your password must be 6 and 10 characters long!</alert></div><div ng-message=\"email\"><alert type=\"danger\" close=\"\">Your email address is invalid!</alert></div><div ng-message=\"pattern\"><alert type=\"danger\" close=\"\">Passwords must match!</alert></div></div><form novalidate name=\"loginform\" accept-charset=\"UTF-8\" role=\"form\" ng-submit=\"loginform.$valid && authCtrl.register(user)\"><fieldset><div class=\"form-group\" ng-class=\"{'has-success': loginform.username.$valid && loginform.name.$dirty, 'has-error': loginform.name.$invalid && loginform.$submitted }\"><input class=\"form-control\" required ng-model=\"user.userName\" placeholder=\"Username\" name=\"username\" type=\"text\"></div><div class=\"form-group\" ng-class=\"{'has-success': loginform.password.$valid && loginform.password.$dirty, 'has-error': loginform.password.$invalid && loginform.$submitted }\"><input class=\"form-control\" minlength=\"6\" required ng-model=\"user.password\" placeholder=\"Password\" name=\"password\" type=\"password\"></div><div class=\"form-group\" ng-class=\"{'has-success': loginform.confirmpassword.$valid && loginform.confirmpassword.$dirty, 'has-error': loginform.confirmpassword.$invalid && loginform.$submitted }\"><input class=\"form-control\" minlength=\"6\" required ng-model=\"user.confirmPassword\" ng-pattern=\"{{user.password}}\" placeholder=\"Confirm Password\" name=\"confirmpassword\" type=\"password\"></div><div class=\"row\"><div class=\"form-group col-xs-6\" ng-class=\"{'has-success': loginform.firstname.$valid && loginform.firstname.$dirty, 'has-error': loginform.firstname.$invalid && loginform.$submitted }\"><input class=\"form-control\" align=\"left\" required ng-model=\"user.givenName\" placeholder=\"First name\" name=\"firstname\" type=\"text\"></div><div class=\"form-group col-xs-6\" ng-class=\"{'has-success': loginform.middlename.$valid && loginform.middlename.$dirty, 'has-error': loginform.middlename.$invalid && loginform.$submitted }\"><input class=\"form-control\" align=\"right\" ng-model=\"user.middleName\" placeholder=\"Middle name\" name=\"middlename\" type=\"text\"></div></div><div class=\"form-group\" ng-class=\"{'has-success': loginform.lastname.$valid && loginform.lastname.$dirty, 'has-error': loginform.lastname.$invalid && loginform.$submitted }\"><input class=\"form-control\" required ng-model=\"user.surName\" placeholder=\"Last Name\" name=\"lastname\" type=\"text\"></div><div class=\"form-group\"><label>Please select your roles:</label><br><div class=\"row\"><div class=\"col-xs-6\" ng-repeat=\"(key,value) in roles\"><p><strong>{{key}}</strong></p><input ng-required=\"isCheckRequired(user.roles)\" type=\"checkbox\" name=\"roles\" checklist-model=\"user.roles\" checklist-value=\"key\" ng-class=\"{'has-success': loginform.roles.$valid && loginform.roles.$dirty, 'has-error': loginform.roles.$invalid && loginform.$submitted }\"></div></div></div><div class=\"form-group\" ng-class=\"{'has-success': loginform.email.$valid && loginform.email.$dirty, 'has-error': loginform.email.$invalid && loginform.$submitted }\"><input class=\"form-control\" required ng-model=\"user.email\" placeholder=\"email\" name=\"email\" type=\"email\"></div></fieldset><input class=\"btn btn-lg btn-primary btn-block\" type=\"submit\" value=\"Register\"></form><input class=\"btn btn-lg btn-default btn-block\" ng-click=\"authCtrl.goBack()\" type=\"submit\" value=\"Go Back\"><div class=\"spinner text-center\" ng-show=\"loading\"><img src=\"http://www.lectulandia.com/wp-content/themes/ubook/images/spinner.gif\" alt=\"Loading\" style=\"width:48px;height:48px\"></div></div></div></div></div>"
  );

}]);
