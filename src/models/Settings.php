<?php

/**
 * Craft JWT Auth plugin for Craft CMS 3.x
 *
 * Enable authentication to Craft through the use of JSON Web Tokens (JWT)
 *
 * @link      https://edenspiekermann.com
 * @copyright Copyright (c) 2019 Mike Pierce
 */

namespace structureit\craftcognitoauth\models;

use craft\base\Model;

/**
 * @author    Mike Pierce
 * @package   CraftCognitoAuth
 * @since     0.1.0
 */
class Settings extends Model
{
    // Public Properties
    // =========================================================================

    /** @var boolean */
    public $autoCreateUser = false;
    /** @var boolean */
    public $autoCreateUserWhenPublicRegistrationDisabled = false;
    /** @var integer */
    public $newUserGroup = 0;
    /** @var boolean */
    public $addLoginLink = false;
    /** @var string */
    public $customizeLoginLinkText = '';
    /** @var string */
    public $userPoolRegion = '';
    /** @var string */
    public $userPoolAppDomain = '';
    /** @var string */
    public $userPoolAppID = '';
    /** @var string */
    public $userPoolID = '';

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            ['autoCreateUser', 'boolean'],
            ['autoCreateUserWhenPublicRegistrationDisabled', 'boolean'],
            ['newUserGroup', 'integer'],
            ['addLoginLink', 'boolean'],
            ['customizeLoginLinkText', 'string'],
            ['userPoolRegion', 'string'],
            ['userPoolAppDomain', 'string'],
            ['userPoolAppID', 'string'],
            ['userPoolID', 'string']
        ];
    }
}
