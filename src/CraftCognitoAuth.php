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
use structureit\craftcognitoauth\web\assets\login\LoginAsset;

use Craft;
use craft\base\Plugin;
use craft\events\RegisterUrlRulesEvent;
use craft\services\Plugins;
use craft\web\UrlManager;
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

        Event::on(
            UrlManager::class,
            UrlManager::EVENT_REGISTER_CP_URL_RULES,
            function (RegisterUrlRulesEvent $event) {
                $event->rules['cognitologin']    = 'craft-cognito-auth/j-w-t/cognito-login';
                $event->rules['logout-redirect'] = 'craft-cognito-auth/j-w-t/logout-redirect';
            }
        );

        // Add login with cognito link to login screen
        Event::on(
            Plugins::class,
            Plugins::EVENT_AFTER_LOAD_PLUGINS,
            function() {
                if (
                    !Craft::$app->getRequest()->getIsConsoleRequest()
                    && $this->getSettings()->addLoginLink
                    && Craft::$app->getRequest()->getIsCpRequest()
                    && Craft::$app->getRequest()->getSegment(1) === 'login'
                ) {
                    $jsCognitoProvider = [
                        'url' => '',
                        'text' => 'Login with Cognito'
                    ];
                    $error = Craft::$app->getSession()->getFlash('error');

                    Craft::$app->getView()->registerAssetBundle(LoginAsset::class);
                    Craft::$app->getView()->registerJs('var cognitoLoginForm = new Craft.CognitoLoginForm(' . json_encode($jsCognitoProvider) . ', ' . json_encode($error) . ');');
                }
            }
        );

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
