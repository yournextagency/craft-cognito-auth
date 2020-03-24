<?php

/**
 * Craft JWT Auth plugin for Craft CMS 3.x
 *
 * Enable authentication to Craft through the use of JSON Web Tokens (JWT)
 *
 * @link      https://edenspiekermann.com
 * @copyright Copyright (c) 2019 Mike Pierce
 */

namespace structureit\craftcognitoauth;

use structureit\craftcognitoauth\services\JWT as JWTService;
use structureit\craftcognitoauth\services\CognitoJWK as CognitoJWKService;
use structureit\craftcognitoauth\models\Settings;

use Craft;
use craft\base\Plugin;
use craft\web\Application;

use yii\base\Event;

/**
 * Class CraftCognitoAuth
 *
 * @author    Mike Pierce
 * @package   CraftCognitoAuth
 * @since     0.1.0
 *
 * @property  JWTService $jWT
 * @property  CognitoJWKService $CognitoJWK
 */
class CraftCognitoAuth extends Plugin
{
    // Static Properties
    // =========================================================================

    /**
     * @var CraftCognitoAuth
     */
    public static $plugin;

    // Public Properties
    // =========================================================================

    /**
     * @var string
     */
    public $schemaVersion = '0.1.0';

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();
        self::$plugin = $this;

        Craft::$app->on(Application::EVENT_INIT, function (Event $event) {
            if (Craft::$app->request->fullPath === 'cognitoauth')
            {
                if (($jwt = self::$plugin->jWT->getJWTFromRequest()))
                {
                    // If the token passes verification
                    if (($token = self::$plugin->jWT->parseAndVerifyJWT($jwt))) {
                        // Look for the user
                        $user = self::$plugin->jWT->getUserByJWT($token);

                        // If we don't have a user, and we're NOT allowed to create one
                        if (!$user && !self::$plugin->jWT->shouldAutoCreateUser()) {
                            print('No craft user found, and autocreate disabled!');
                            die();
                        } elseif (!$user) { // If we don't have a user, but we ARE allowed to create one
                            $user = self::$plugin->jWT->createUserByJWT($token);
                        }

                        // Attempt to login as the user we have found or created
                        if (isset($user->id) && $user->id) {
                            Craft::$app->user->loginByUserId($user->id);
                            // redirect back to the homepage
                            Craft::$app->getResponse()->redirect(UrlHelper::baseUrl())->send();
                            die();
                        } else {
                            print('Unknown error getting/creating user!');
                            die();
                        }
                    } else {
                        print('Invalid token!');
                        die();
                    }
                } else {
                    // No jwt in QueryParams, try using javascript to extract from SearchParams
                    print('
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
                    ');
                    die();
                }
            }
        });

        Craft::info(
            Craft::t(
                'craft-cognito-auth',
                '{name} plugin loaded',
                ['name' => $this->name]
            ),
            __METHOD__
        );
    }

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    protected function createSettingsModel()
    {
        return new Settings();
    }

    /**
     * @inheritdoc
     */
    protected function settingsHtml(): string
    {
        return Craft::$app->view->renderTemplate(
            'craft-cognito-auth/settings',
            [
                'settings' => $this->getSettings()
            ]
        );
    }
}
