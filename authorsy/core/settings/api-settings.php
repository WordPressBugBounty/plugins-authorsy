<?php
/**
 * Class Api Settings
 *
 * @package Authorsy
 */
namespace Authorsy\Core\Settings;
defined( 'ABSPATH' ) || exit;

use Authorsy\Base\Api;
use Authorsy\Utils\Singleton;

class Api_Settings extends Api {
    use Singleton;

    /**
     * Store api namespace
     *
     * @var string
     */
    protected $namespace = 'authorsy/v1';

    /**
     * Store rest base
     *
     * @var string
     */
    protected $rest_base = 'settings';

    /**
     * Register rest route
     *
     * @return  void
     */
    public function register_routes() {
        register_rest_route(
            $this->namespace, $this->rest_base, [
                [
                    'methods'             => \WP_REST_Server::READABLE,
                    'callback'            => [$this, 'get_settings'],
                    'permission_callback' => function () {
                        return current_user_can('manage_options');
                    },
                ],
                [
                    'methods'             => \WP_REST_Server::EDITABLE,
                    'callback'            => [$this, 'update_settings'],
                    'permission_callback' => function () {
                        return current_user_can('manage_options');
                    },
                ],
            ]
        );
 
    }

    /**
     * Get settings
     *
     * @return  JSON
     */
    public function get_settings() {
        $settings = apply_filters( 'authorsy_settings', authorsy_get_settings() );

        $data = [
            'status_code' => 200,
            'success'     => 1,
            'message'     => esc_html__( 'Get all settings', 'authorsy' ),
            'data'        => $settings,
        ];

        return rest_ensure_response( $settings );
    }

    /**
     * Update settings
     *
     * @param   WP_Rest_Request  $request
     *
     * @return  JSON
     */
    public function update_settings( $request ) {
        // Rate limiting to prevent abuse
        $user_id = get_current_user_id();
        $rate_limit_key = 'authorsy_settings_rate_limit_' . $user_id;
        $rate_limit = get_transient( $rate_limit_key );
        
        if ( $rate_limit && $rate_limit >= 10 ) { // Max 10 requests per hour
            return new \WP_Error(
                'rate_limit_exceeded',
                __( 'Too many requests. Please try again later.', 'authorsy' ),
                [ 'status' => 429 ]
            );
        }
        
        // Increment rate limit counter
        if ( $rate_limit ) {
            set_transient( $rate_limit_key, $rate_limit + 1, HOUR_IN_SECONDS );
        } else {
            set_transient( $rate_limit_key, 1, HOUR_IN_SECONDS );
        }
        
        $options = json_decode( $request->get_body(), true );

        $nonce_check = $this->verify_nonce( $request );
        if ( is_wp_error( $nonce_check ) ) {
            return $nonce_check;
        }
        /**
         * Added temporary for leagacy sass. It will remove in future.
         */
        $data = [
            'status_code' => 200,
            'success'     => 1,
            'message'     => esc_html__( 'Settings successfully updated', 'authorsy' ),
            'data'        => authorsy_get_settings(),
        ];

     

        if ( $options ) {
            foreach ( $options as $key => $value ) {
                // Sanitize CSS fields to prevent XSS
                if ( $key === 'ea_custom_css' && ! empty( $value ) ) {
                    $value = $this->sanitize_css( $value );
                    
                    // Additional validation - ensure it's valid CSS
                    if ( ! $this->is_valid_css( $value ) ) {
                        return new \WP_Error(
                            'invalid_css',
                            __( 'Invalid CSS provided. Please check your CSS syntax.', 'authorsy' ),
                            [ 'status' => 400 ]
                        );
                    }
                }
                authorsy_update_option( $key, $value );
            }
        }

        $data['data'] = authorsy_get_settings();

        return rest_ensure_response( $data );
    }

    /**
     * Sanitize CSS input to prevent XSS attacks
     *
     * @param string $css The CSS string to sanitize
     * @return string Sanitized CSS
     */
    private function sanitize_css( $css ) {
        // Remove any script tags and their content
        $css = preg_replace( '/<script[^>]*>.*?<\/script>/is', '', $css );
        
        // Remove any HTML tags
        $css = strip_tags( $css );
        
        // Remove JavaScript protocol handlers
        $css = preg_replace( '/javascript\s*:/i', '', $css );
        
        // Remove any expression() functions that could execute code
        $css = preg_replace( '/expression\s*\(/i', '', $css );
        
        // Remove any url() functions with javascript: protocol
        $css = preg_replace( '/url\s*\(\s*["\']?\s*javascript\s*:/i', '', $css );
        
        // Remove any @import statements that could be dangerous
        $css = preg_replace( '/@import\s+url\s*\(\s*["\']?\s*javascript\s*:/i', '', $css );
        
        // Remove any CSS comments that might contain malicious content
        $css = preg_replace( '/\/\*.*?\*\//s', '', $css );
        
        // Remove any newlines and tabs to prevent potential injection
        $css = str_replace( [ "\n", "\r", "\t" ], '', $css );
        
        return trim( $css );
    }

    /**
     * Validate if the provided string contains valid CSS
     *
     * @param string $css The CSS string to validate
     * @return bool True if valid CSS, false otherwise
     */
    private function is_valid_css( $css ) {
        // Basic CSS validation - check for common CSS patterns
        // This is a simplified validation - in production you might want more sophisticated validation
        
        // Check if it contains only allowed CSS characters and basic structure
        if ( empty( $css ) ) {
            return true; // Empty CSS is valid
        }
        
        // Remove all whitespace for easier validation
        $css = preg_replace( '/\s+/', '', $css );
        
        // Basic CSS structure validation
        // Should contain at least one selector and property
        if ( ! preg_match( '/^[a-zA-Z0-9\-\_\#\.\,\s\{\}\:\;\=\"\'\(\)\[\]\>\<\+\~\|\&\*\^\$\%\!\?\/\\]+$/', $css ) ) {
            return false;
        }
        
        // Check for balanced braces
        $brace_count = 0;
        for ( $i = 0; $i < strlen( $css ); $i++ ) {
            if ( $css[$i] === '{' ) {
                $brace_count++;
            } elseif ( $css[$i] === '}' ) {
                $brace_count--;
                if ( $brace_count < 0 ) {
                    return false; // Unbalanced braces
                }
            }
        }
        
        return $brace_count === 0; // All braces should be balanced
    }
}
