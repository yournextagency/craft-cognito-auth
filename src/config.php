<?php

/**
 * Craft JWT Auth plugin for Craft CMS 3.x
 *
 * Enable authentication to Craft through the use of JSON Web Tokens (JWT)
 *
 * @link      https://edenspiekermann.com
 * @copyright Copyright (c) 2019 Mike Pierce
 */

/**
 * Craft JWT Auth config.php
 *
 * This file exists only as a template for the Craft JWT Auth settings.
 * It does nothing on its own.
 *
 * Don't edit this file, instead copy it to 'craft/config' as 'craft-cognito-auth.php'
 * and make your changes there to override default settings.
 *
 * Once copied to 'craft/config', this file will be multi-environment aware as
 * well, so you can have different settings groups for each environment, just as
 * you do for 'general.php'
 */

return [
    // TODO: Make these actually do something...

    // If enabled, will automatically create a public user when provided with a verified JWT
    "autoCreateUser" => true,

    // Allow creating users even when Public Registration is disabled in craft's settings
    "autoCreateUserWhenPublicRegistrationDisabled" => false,

    // Choose a user group that users will be added to when created from Cognito
    "newUserGroup" => 0,

    // Enable CP Login Link - Toggles the visibility of the Login with Cognito button on the Control Panel's login screen
    "addLoginLink" => false,

    // The text that the login button should show on the Control Panel\'s login screen. Default: `Login with Cognito`
    "customizeLoginLinkText" => '',

    // URL to redirect to after user has logged in successfully. Defaults to the current site's base URL
    "redirectURL" => '',

    // The AWS Region where the User Pool is hosted
    "userPoolRegion" => '',

    // App Domain - Used to generate the login link for the Login with Cognito button
    "userPoolAppDomain" => '',

    // App Client ID - Used to generate a login link and to verify the JWK was created for the correct pool
    "userPoolAppID" => '',

    // Required to get the key Cognito used to sign the JWK
    "userPoolID" => '',
];
