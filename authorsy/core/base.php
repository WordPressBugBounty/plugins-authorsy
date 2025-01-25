<?php
/**
 * Appoints base file
 *
 * @since 1.0.0
 *
 * @package Authorsy
 */

namespace Authorsy\Core;
defined( 'ABSPATH' ) || exit;

use Authorsy\Core\Authors\Author;
use Authorsy\Core\Ratings;
use Authorsy\Utils\Singleton; 

/**
 * Base Class
 *
 * @since 1.0.0
 */
class Base {

    use Singleton;

    /**
     * Initialize all modules.
     *
     * @since 1.0.0
     *
     * @return void
     */
    public function init() {
        // Initialize classes.   
        Settings\Api_Settings::instance();  
        EnqueueInline\Enqueue_Inline::instance()->init();
        Admin\Hooks::instance()->init();
        Authors\Hooks::instance()->init();
        Authors\Api_Author::instance();
        Authors\Author_Meta::instance()->init(); 
        Like_Dislike\Like_Dislike_Meta::instance()->init();
        Like_Dislike\Api_Like_Dislike::instance();
        Like_Dislike\Hooks::instance()->init(); 
    }
}


