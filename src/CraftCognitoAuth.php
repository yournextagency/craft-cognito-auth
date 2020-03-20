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
            if (Craft::$app->request->fullPath === 'cognitologin')
            {
                if (isset(Craft::$app->request->queryParams['jwt']))
                {
                    $tmp = Craft::$app->request->queryParams['jwt'];
                    $token = self::$plugin->jWT->parseAndVerifyJWT($tmp);

                    // If the token passes verification...
                    if ($token) {
                        // Look for the user
                        $user = self::$plugin->jWT->getUserByJWT($token);

                        // If we don't have a user, but we're allowed to create one...
                        if (!$user) {
                            $user = self::$plugin->jWT->createUserByJWT($token);
                        }

                        // Attempt to login as the user we have found or created
                        if (isset($user->id) && $user->id) {
                            Craft::$app->user->loginByUserId($user->id);
                        }
                    }
                    Craft::$app->getResponse()->redirect(UrlHelper::baseUrl())->send();
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
