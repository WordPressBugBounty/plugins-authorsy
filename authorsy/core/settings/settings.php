<?php
/**
 * Global settings for authorsy
 *
 * @package Authorsy
 */

// Exit if accessed directly
defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'authorsy_get_option' ) ) {
    /**
     * Get option for authorsy
     *
     * @since 1.0.0
     * @return  mixed
     */
    function authorsy_get_option( $key = '', $default = false ) {
        $options = get_option( 'authorsy_settings' );
        $value   = $default;

        if ( isset( $options[$key] ) ) {
            $value = ! empty( $options[$key] ) ? $options[$key] : $default;
        }

        return $value;
    }
}

if ( ! function_exists( 'authorsy_update_option' ) ) {

    /**
     * Update option
     *
     * @param   string  $key
     *
     * @since 1.0.0
     *
     * @return  boolean
     */
    function authorsy_update_option( $key = '', $value = false ) {
        if ( ! $key ) {
            return false;
        }

        // Get the current settings.
        $options = get_option( 'authorsy_settings', [] );

        // Set new settings value.
        $options[$key] = $value;

        // Update the settings.
        $did_update = update_option( 'authorsy_settings', $options );

        return $did_update;
    }
}

if ( ! function_exists( 'authorsy_get_settings' ) ) {

    /**
     * Get settings
     *
     * Retrieve all plugin settings
     *
     * @since 1.0.0
     *
     * @return  array Authorsy Settings
     */
    function authorsy_get_settings() {
        // Get the option key.
        $settings = get_option( 'authorsy_settings' );

        return apply_filters( 'authorsy_get_settings', $settings );
    }
}
 