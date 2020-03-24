<?php

/**
 * Craft JWT Auth plugin for Craft CMS 3.x
 *
 * Enable authentication to Craft through the use of JSON Web Tokens (JWT)
 *
 * @link      https://edenspiekermann.com
 * @copyright Copyright (c) 2019 Mike Pierce
 */

namespace structureit\craftcognitoauth\controllers;

use Craft;
use craft\web\View;
use craft\helpers\UrlHelper;
use craft\web\Controller;
use structureit\craftcognitoauth\CraftCognitoAuth;

/**
 * @author    Mike Pierce
 * @package   CraftCognitoAuth
 * @since     0.1.0
 */
class JWTController extends Controller
{

    // Protected Properties
    // =========================================================================

    /**
     * @var    bool|array Allows anonymous access to this controller's actions.
     *         The actions must be in 'kebab-case'
     * @access protected
     */
    protected $allowAnonymous = [
        'cognito-login',
        'logout-redirect'
    ];

    // Public Methods
    // =========================================================================

    public function actionCognitoLogin()
    {
        if (($jwt = CraftCognitoAuth::$plugin->jWT->getJWTFromRequest()))
        {
            // If the token passes verification
            if (($token = CraftCognitoAuth::$plugin->jWT->parseAndVerifyJWT($jwt)))
            {
                // Look for the user
                $user = CraftCognitoAuth::$plugin->jWT->getUserByJWT($token);

                if (!$user && !CraftCognitoAuth::$plugin->jWT->shouldAutoCreateUser())
                {   // If we don't have a user, and we're NOT allowed to create one
                    return $this->renderTemplate('error', [
                            'message' => 'No Existing User Found! (And not allowed to create new users)'
                        ], View::TEMPLATE_MODE_CP);
                }
                elseif (!$user)
                {   // If we don't have a user, but we ARE allowed to create one
                    $user = CraftCognitoAuth::$plugin->jWT->createUserByJWT($token);
                }


                if (isset($user->id) && $user->id)
                {   // Attempt to login as the user we have found or created
                    Craft::$app->user->loginByUserId($user->id);
                    // redirect back to the homepage
                    return $this->redirect(UrlHelper::baseUrl());
                }
                else
                {   // no user ID, something went wrong...
                    return $this->renderTemplate('error', [
                            'message' => 'Unknown Error Getting/Creating User!'
                        ], View::TEMPLATE_MODE_CP);
                }
            }
            else
            {   // parseToken or verifyToken failed
                return $this->renderTemplate('error', [
                        'message' => 'Invalid Token!'
                    ], View::TEMPLATE_MODE_CP);
            }
        }
        else
        {   // No jwt in QueryParams, try using javascript to extract from SearchParams
            return '
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <script type="text/javascript">
            var params = window.location.hash.substr(1);
            var searchParams = new URLSearchParams(params);
            var id_token = searchParams.get("id_token");
            if (id_token !== null) {
                window.location.replace(window.location.pathname + "?jwt=" + id_token);
                document.write("Redirecting...");
            } else {
                document.write("No Token Found!");
            }
        </script>
    </head>
    <body style="font-family: Verdana, Geneva, Tahoma, sans-serif;">
        <noscript>
            This page uses javascript to move the id_token to the query parameters. Either enable Javascript,
            or manually edit the "#id_token=" part of the url to "?jwt=".
        </noscript>
    </body>
</html>
            ';
        }
    }

    /**
     * @return mixed
     */
    public function actionLogoutRedirect()
    {
        \Craft::$app->getUser()->logout(false);
        $this->redirect($_SERVER['HTTP_REFERER']);
    }
}
