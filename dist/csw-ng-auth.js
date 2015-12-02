(function (ng) {

    var mod = ng.module('authModule', ['ngCookies', 'ngRoute', 'checklist-model', 'ngStorage']);
    mod.constant('defaultStatus', {status: false});

    mod.config(['$routeProvider', 'authServiceProvider', function ($routeProvider, auth) {
        var authConfig = auth.getValues();
        $routeProvider
            .when(authConfig.loginPath, {
                templateUrl: 'src/templates/login.html',
                controller: 'authController',
                controllerAs: 'authCtrl'
            })
            .when(authConfig.registerPath, {
                templateUrl: 'src/templates/register.html',
                controller: 'authController',
                controllerAs: 'authCtrl'
            })
            .when(authConfig.forgotPassPath, {
                templateUrl: 'src/templates/forgotPass.html',
                controller: 'authController',
                controllerAs: 'authCtrl'
            })
            .when(authConfig.forbiddenPath, {
                templateUrl: 'src/templates/forbidden.html',
                controller: 'authController',
                controllerAs: 'authCtrl'
            });
    }]);

    mod.config(['$httpProvider', 'authServiceProvider', function ($httpProvider, authServiceProvider) {
        $httpProvider.interceptors.push(['$q', '$log', '$location', function ($q, $log, $location) {
            return {
                'responseError': function (rejection) {
                    if(rejection.status === 401){
                        $log.debug('error 401', rejection);
                        $location.path(authServiceProvider.getValues().loginPath);
                    }
                    if(rejection.status === 403){
                        $log.debug('error 403', rejection);
                        $location.path(authServiceProvider.getValues().forbiddenPath);
                    }
                    return $q.reject(rejection);
                },
                request: function (config) {
                    config.withCredentials = true;
                    return config;
                },
                response: function(res) {
                    return res;
                }

            };
        }]);
    }]);
})(window.angular);



/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
(function (ng) {

    var mod = ng.module('authModule');

    mod.controller('authController', ['$scope', '$cookies', '$location', 'authService', 'defaultStatus','$log', function ($scope, $cookies, $location, authSvc, defaultStatus, $log) {
        this.errorctrl = defaultStatus;
        $scope.roles = authSvc.getRoles();
        authSvc.userAuthenticated().then(function(data){
            $scope.currentUser = data.data;
            if ($scope.currentUser !== "" && !$scope.menuitems){
                $scope.setMenu($scope.currentUser);
            }
        });
        $scope.loading = false;
        $scope.$on('logged-in', function (events, user) {
            $scope.currentUser = user.data;
            $scope.setMenu($scope.currentUser);
        });

        $scope.setMenu = function(user){
            $scope.menuitems=[];
            for (var i=0; i<user.roles.length; i++)
            {
                for (var rol in $scope.roles){
                    if (user.roles[i] === rol) {
                        for (var menu in $scope.roles[rol])
                            $scope.menuitems.push($scope.roles[rol][menu]);
                    }
                }
            }
        };

        $scope.isAuthenticated = function(){
            return !!$scope.currentUser;
        };


        this.login = function (user) {
            var self = this;
            if (user && user.userName && user.password) {
                $scope.loading = true;
                authSvc.login(user).then(function (data) {
                    $log.info("user", data);
                }, function (data) {
                    self.errorctrl = {status: true, type: "danger", msg: ":" + data.data};
                    $log.error("Error", data);
                }).finally(function(){
                    $scope.loading = false;
                });
            }
        };

        $scope.logout = function () {
            authSvc.logout().then(function(){
                $scope.currentUser = "";

            });
        };

        $scope.log = function(obj){
            $log.debug(obj);
        };

        this.close = function () {
            this.errorctrl = defaultStatus;
        };

        this.registration = function () {
            authSvc.registration();
        };

        this.register = function (newUser) {
            var self = this;
            if (newUser.password !== newUser.confirmPassword) {
                this.errorctrl = {status: true, type: "warning", msg: ": Passwords must be equals"};
            } else {
                $scope.loading = true;
                authSvc.register(newUser).then(function (data) {
                    self.errorctrl = {status: true, type: "success", msg: ":" + " User registered successfully"};
                }, function (data) {
                    self.errorctrl = {status: true, type: "danger", msg: ":" + data.data.substring(66)};
                }).finally(function(){
                    $scope.loading = false;
                });
            }
        };

        this.goToForgotPass = function(){
            authSvc.goToForgotPass();
        };

        this.forgotPass = function(user){
            var self = this;
            if (user){
                $scope.loading = true;
                authSvc.forgotPass(user).then(function(data){
                }, function(data){
                        self.errorctrl = {status: true, type: "danger", msg: ":" + data.data.substring(66)};
                    }
                ).finally(function(){
                       $scope.loading = false;
                    });
            }else {
                self.errorctrl = {status: true, type: "danger", msg: ":" + "You must to enter an email address"}
            }
        };


        $scope.goToLogin = function () {
            authSvc.goToLogin();
        };

        this.goBack = function () {
            authSvc.goToBack();
        };

        $scope.goToSuccess = function(){
            authSvc.goToSuccess();
        };
    }]);

})(window.angular);


/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
(function(ng){
    
    var mod = ng.module('authModule');
    
    mod.directive('loginButton',[function(){
        return {
            scope:{},
            restrict: 'E',
            templateUrl: 'src/templates/button.html',
            controller: 'authController'
        };                    
    }]);
})(window.angular);


(function (ng) {

    var mod = ng.module('authModule');

    mod.provider('authService', function () {

        //Default
        var values = {
            apiUrl: 'api/users/',
            successPath: '/product',
            loginPath: '/login',
            forgotPassPath: '/forgotPass',
            registerPath: '/register',
            logoutRedirect: '/login',
            loginURL: 'login',
            registerURL: 'register',
            logoutURL: 'logout',
            forgotPassURL: 'forgot',
            forbiddenPath: '/forbidden',
            meURL: '/me'
        };

        //Default Roles
        var roles = {
            'user': 'Client',
            'provider': 'Provider'
        };

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

        this.$get = ['$cookies', '$location', '$http','$rootScope','$localStorage', '$sessionStorage', function ($cookies, $location, $http, $rootScope, $localStorage, $sessionStorage) {
            return {
                getRoles: function(){
                    return roles;
                },
                login: function (user) {
                    return $http.post(values.apiUrl+values.loginURL, user).then(function (data) {
                        $rootScope.$broadcast('logged-in', data);
                        $location.path(values.successPath);
                    });
                },
                getConf: function () {
                    return values;
                },
                logout: function () {
                    return $http.get(values.apiUrl+values.logoutURL).then(function () {
                        $location.path(values.logoutRedirect);
                    });
                },
                register: function (user) {
                    return $http.post(values.apiUrl+values.registerURL, user).then(function (data) {
                        $location.path(values.loginPath);
                    });
                },
                forgotPass: function (user) {
                    return $http.post(values.apiUrl+values.forgotPassURL, user).then(function (data) {
                        $location.path(values.loginPath);
                    });
                },
                registration: function () {
                    $location.path(values.registerPath);
                },
                goToLogin: function () {
                    $location.path(values.loginPath);
                },
                goToForgotPass: function(){
                    $location.path(values.forgotPassPath);
                },
                goToBack: function () {
                    $location.path(values.loginPath);
                },
                goToSuccess: function () {
                    $location.path(values.successPath);
                },
                goToForbidden: function(){
                    $location.path(values.forbiddenPath);
                },
                userAuthenticated: function(){
                    return $http.get(values.apiUrl + values.meURL);
                }
            };
        }];
    });
})(window.angular);
angular.module('authModule').run(['$templateCache', function($templateCache) {
  'use strict';

  $templateCache.put('src/templates/button.html',
    "<button ng-hide=\"isAuthenticated()\" type=\"button\" class=\"btn btn-default navbar-btn\" ng-click=\"goToLogin()\">\n" +
    "    <span class=\"glyphicon glyphicon-user\" aria-hidden=\"true\"></span> Login\n" +
    "</button>\n" +
    "\n" +
    "<div ng-show=\"isAuthenticated()\" class=\"btn-group\">\n" +
    "    <button type=\"button\" class=\"btn btn-default dropdown-toggle navbar-btn\" data-toggle=\"dropdown\" aria-haspopup=\"true\"\n" +
    "            aria-expanded=\"false\">\n" +
    "        {{currentUser.userName}} <span class=\"caret\"></span>\n" +
    "    </button>\n" +
    "    <ul class=\"dropdown-menu\">\n" +
    "        <li ng-repeat=\"menuitem in menuitems\">\n" +
    "            <a ng-href='{{menuitem.url}}'><span class='glyphicon glyphicon-{{menuitem.icon}}' aria-hidden='true'></span> {{menuitem.label}}</a></li>\n" +
    "        </li>\n" +
    "        <li>\n" +
    "            <a href ng-click=\"logout()\">\n" +
    "                <span class=\"glyphicon glyphicon-log-out\" aria-hidden=\"true\"></span> Logout\n" +
    "            </a>\n" +
    "        </li>\n" +
    "    </ul>\n" +
    "</div>\n"
  );


  $templateCache.put('src/templates/forbidden.html',
    "<div class=\"jumbotron\">\r" +
    "\n" +
    "    <h1>Oups,Forbidden!!</h1>\r" +
    "\n" +
    "    <p> You don't have permissions for this resource!!</p>\r" +
    "\n" +
    "    <p><a class=\"btn btn-primary btn-lg\" ng-click=\"goToSuccess()\" role=\"button\">Back</a></p>\r" +
    "\n" +
    "</div>\r" +
    "\n"
  );


  $templateCache.put('src/templates/forgotPass.html',
    "<div>\r" +
    "\n" +
    "    <div class=\"col-md-5 col-md-offset-4\">\r" +
    "\n" +
    "        <div class=\"col-md-12\" ng-show=\"authCtrl.errorctrl.status\" ng-message=\"show\">\r" +
    "\n" +
    "            <div class=\"alert alert-{{authCtrl.errorctrl.type}}\" role=\"alert\">\r" +
    "\n" +
    "                <button type=\"button\" class=\"close\" ng-click=\"authCtrl.close()\" aria-label=\"Close\"><span aria-hidden=\"true\">&times;</span></button>\r" +
    "\n" +
    "                <strong>{{authCtrl.errorctrl.type| uppercase}}</strong> {{authCtrl.errorctrl.msg}}\r" +
    "\n" +
    "            </div>\r" +
    "\n" +
    "        </div>\r" +
    "\n" +
    "        <div class=\"col-md-12\">\r" +
    "\n" +
    "            <div class=\"panel panel-default\">\r" +
    "\n" +
    "                <div class=\"panel-heading\">\r" +
    "\n" +
    "                    <h2 class=\"panel-title\">Password assistance</h2>\r" +
    "\n" +
    "                </div>\r" +
    "\n" +
    "                <div class=\"panel-body\">\r" +
    "\n" +
    "                    <p>Enter the email address associated with your account, then click <strong>Send Email</strong>. We'll send you a link to a page where you can easily create a new password.</p>\r" +
    "\n" +
    "                    <form name=\"forgotPassform\" accept-charset=\"UTF-8\" role=\"form\">\r" +
    "\n" +
    "                        <div class=\"form-group\">\r" +
    "\n" +
    "                            <input class=\"form-control\" required ng-model=\"user.email\" placeholder=\"Email\" name=\"email\" type=\"email\">\r" +
    "\n" +
    "                        </div>\r" +
    "\n" +
    "                        <input class=\"btn btn-lg btn-success btn-block\" ng-click=\"authCtrl.forgotPass(user)\" type=\"submit\" value=\"Send Email\">\r" +
    "\n" +
    "                        <input class=\"btn btn-lg btn-default btn-block\" ng-click=\"authCtrl.goBack()\" type=\"submit\" value=\"Go Back\">\r" +
    "\n" +
    "                    </form>\r" +
    "\n" +
    "                    <div class=\"spinner text-center\" ng-show=\"loading\">\r" +
    "\n" +
    "                        <img src=\"http://www.lectulandia.com/wp-content/themes/ubook/images/spinner.gif\" alt=\"Loading\" style=\"width:48px;height:48px;\">\r" +
    "\n" +
    "                    </div>\r" +
    "\n" +
    "                </div>\r" +
    "\n" +
    "            </div>\r" +
    "\n" +
    "        </div>\r" +
    "\n" +
    "    </div>\r" +
    "\n" +
    "</div>\r" +
    "\n" +
    "\r" +
    "\n"
  );


  $templateCache.put('src/templates/login.html',
    "<div>\r" +
    "\n" +
    "    <div class=\"col-md-5 col-md-offset-4\">\r" +
    "\n" +
    "        <div class=\"col-md-12\" ng-show=\"authCtrl.errorctrl.status\" ng-message=\"show\">\r" +
    "\n" +
    "            <div class=\"alert alert-{{authCtrl.errorctrl.type}}\" role=\"alert\">\r" +
    "\n" +
    "                <button type=\"button\" class=\"close\" ng-click=\"authCtrl.close()\" aria-label=\"Close\"><span aria-hidden=\"true\">&times;</span></button>\r" +
    "\n" +
    "                <strong>{{authCtrl.errorctrl.type| uppercase}}</strong> {{authCtrl.errorctrl.msg}}\r" +
    "\n" +
    "            </div>\r" +
    "\n" +
    "        </div>\r" +
    "\n" +
    "        <div class=\"col-md-12\">\r" +
    "\n" +
    "            <div class=\"panel panel-default\">\r" +
    "\n" +
    "                <div class=\"panel-heading\">\r" +
    "\n" +
    "                    <h3 class=\"panel-title\">Please Login</h3>\r" +
    "\n" +
    "                </div>\r" +
    "\n" +
    "                <div class=\"panel-body\">\r" +
    "\n" +
    "                    <form name=\"loginform\" accept-charset=\"UTF-8\" role=\"form\">\r" +
    "\n" +
    "                        <div class=\"form-group\">\r" +
    "\n" +
    "                            <input class=\"form-control\" required ng-model=\"user.userName\" placeholder=\"Username or Email\" name=\"username\" type=\"text\">\r" +
    "\n" +
    "                        </div>\r" +
    "\n" +
    "                        <div class=\"form-group\">\r" +
    "\n" +
    "                            <div class=\"text-right\">\r" +
    "\n" +
    "                                <a align=\"right\" ng-click=\"authCtrl.goToForgotPass()\">Forgot your password?</a>\r" +
    "\n" +
    "                            </div>\r" +
    "\n" +
    "                            <input class=\"form-control\" required ng-model=\"user.password\" placeholder=\"Password\" name=\"password\" type=\"password\" >\r" +
    "\n" +
    "                        </div>\r" +
    "\n" +
    "                        <div class=\"checkbox\">\r" +
    "\n" +
    "                            <label>\r" +
    "\n" +
    "                                <input  name=\"rememberMe\" type=\"checkbox\" ng-model=\"user.rememberMe\" value=\"false\"> Remember Me\r" +
    "\n" +
    "                            </label>\r" +
    "\n" +
    "                        </div>\r" +
    "\n" +
    "                        <input class=\"btn btn-lg btn-success btn-block\" ng-click=\"authCtrl.login(user)\" type=\"submit\" value=\"Login\">\r" +
    "\n" +
    "                    </form>\r" +
    "\n" +
    "                    <button class=\"btn btn-lg btn-default btn-block\" ng-click=\"authCtrl.registration()\">Create an account</button>\r" +
    "\n" +
    "                    <div class=\"spinner text-center\" ng-show=\"loading\">\r" +
    "\n" +
    "                        <img src=\"http://www.lectulandia.com/wp-content/themes/ubook/images/spinner.gif\" alt=\"Loading\" style=\"width:48px;height:48px;\">\r" +
    "\n" +
    "                    </div>\r" +
    "\n" +
    "                </div>\r" +
    "\n" +
    "            </div>\r" +
    "\n" +
    "        </div>\r" +
    "\n" +
    "    </div>\r" +
    "\n" +
    "</div>\r" +
    "\n"
  );


  $templateCache.put('src/templates/register.html',
    "\r" +
    "\n" +
    "<div>\r" +
    "\n" +
    "    <div class=\"col-md-5 col-md-offset-4\">\r" +
    "\n" +
    "        <div class=\"panel panel-default\">\r" +
    "\n" +
    "            <div class=\"panel-heading\">\r" +
    "\n" +
    "                <h3 class=\"panel-title\">Please Register</h3>\r" +
    "\n" +
    "                <div style=\"padding-top: 30px;\" class=\"col-md-12\" ng-show=\"authCtrl.errorctrl.status\" ng-message=\"show\">\r" +
    "\n" +
    "                    <div   class=\"alert alert-{{authCtrl.errorctrl.type}}\" role=\"alert\">\r" +
    "\n" +
    "                        <button type=\"button\" class=\"close\" ng-click=\"authCtrl.close()\" aria-label=\"Close\"><span aria-hidden=\"true\">&times;</span></button>\r" +
    "\n" +
    "                        <strong>{{authCtrl.errorctrl.type| uppercase}}</strong> {{authCtrl.errorctrl.msg}}\r" +
    "\n" +
    "                    </div>\r" +
    "\n" +
    "                </div>\r" +
    "\n" +
    "            </div>\r" +
    "\n" +
    "            <div class=\"panel-body\">\r" +
    "\n" +
    "                <form name=\"loginform\" accept-charset=\"UTF-8\" role=\"form\">\r" +
    "\n" +
    "                    <div class=\"form-group\">\r" +
    "\n" +
    "                        <input class=\"form-control\" required ng-model=\"user.userName\" placeholder=\"Username\" name=\"username\" type=\"text\">\r" +
    "\n" +
    "                    </div>\r" +
    "\n" +
    "                    <div class=\"form-group\">\r" +
    "\n" +
    "                        <input class=\"form-control\" required ng-model=\"user.password\" placeholder=\"Password\" name=\"password\" type=\"password\" >\r" +
    "\n" +
    "                    </div>\r" +
    "\n" +
    "                    <div class=\"form-group\">\r" +
    "\n" +
    "                        <input class=\"form-control\" required ng-model=\"user.confirmPassword\" placeholder=\"Confirm Password\" name=\"confirmpassword\" type=\"password\" >\r" +
    "\n" +
    "                    </div>\r" +
    "\n" +
    "                    <div class=\"row\">\r" +
    "\n" +
    "                        <div class=\"form-group col-xs-6\">\r" +
    "\n" +
    "                            <input class=\"form-control\" align=\"left\" required ng-model=\"user.givenName\" placeholder=\"First name\" name=\"firstname\" type=\"text\" >\r" +
    "\n" +
    "                        </div>\r" +
    "\n" +
    "                        <div class=\"form-group col-xs-6\">\r" +
    "\n" +
    "                            <input class=\"form-control\" align=\"right\" required ng-model=\"user.middleName\" placeholder=\"Middle name\" name=\"middlename\" type=\"text\" >\r" +
    "\n" +
    "                        </div>\r" +
    "\n" +
    "                    </div>\r" +
    "\n" +
    "                    <div class=\"form-group\">\r" +
    "\n" +
    "                        <input class=\"form-control\" required ng-model=\"user.surName\" placeholder=\"Last Name\" name=\"lastname\" type=\"text\" >\r" +
    "\n" +
    "                    </div>\r" +
    "\n" +
    "                    <div class=\"form-group\">\r" +
    "\n" +
    "                        <label> Please select your roles: </label><br>\r" +
    "\n" +
    "                        <!--<select class=\"form-control\" ng-options=\"rol as value.label for value in roles\" name=\"SelectRole\" ng-model=\"user.role\" required></select>-->\r" +
    "\n" +
    "                        <div class=\"row\">\r" +
    "\n" +
    "                            <div class=\"col-xs-6\" ng-repeat=\"(key,value) in roles\">\r" +
    "\n" +
    "                                <p><strong> {{key}} </strong></p><input type=\"checkbox\" checklist-model=\"user.roles\" checklist-value=\"key\">\r" +
    "\n" +
    "                            </div>\r" +
    "\n" +
    "                        </div>\r" +
    "\n" +
    "                    </div>\r" +
    "\n" +
    "                    <div class=\"form-group\">\r" +
    "\n" +
    "                        <input class=\"form-control\" required ng-model=\"user.email\" placeholder=\"email\" name=\"email\" type=\"email\" >\r" +
    "\n" +
    "                    </div>\r" +
    "\n" +
    "                    <input class=\"btn btn-lg btn-primary btn-block\" ng-click=\"authCtrl.register(user)\" type=\"submit\" value=\"Register\">\r" +
    "\n" +
    "                    <input class=\"btn btn-lg btn-default btn-block\" ng-click=\"authCtrl.goBack()\" type=\"submit\" value=\"Go Back\">\r" +
    "\n" +
    "                </form>\r" +
    "\n" +
    "                <div class=\"spinner text-center\" ng-show=\"loading\">\r" +
    "\n" +
    "                    <img src=\"http://www.lectulandia.com/wp-content/themes/ubook/images/spinner.gif\" alt=\"Loading\" style=\"width:48px;height:48px;\">\r" +
    "\n" +
    "                </div>\r" +
    "\n" +
    "            </div>\r" +
    "\n" +
    "        </div>\r" +
    "\n" +
    "    </div>\r" +
    "\n" +
    "</div>\r" +
    "\n"
  );

}]);
