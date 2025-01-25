<?php

/**
 * Inline Enqueue class
 *
 * @package Authorsy
 */

namespace Authorsy\Core\EnqueueInline;

use Authorsy\Utils\Singleton;
use Authorsy;

/**
 * Class Enqueue_Inline
 */
class Enqueue_Inline
{
    use Singleton;

    /**
     * Initialize the shortcode class
     *
     * @return  void
     */
    public function init()
    {
        add_action('wp_head', array($this, 'custom_inline_css'));
    }

    /**
     * Custom inline css
     */
    public function custom_inline_css()
    {
        $custom_css  = '';
        $settings = authorsy_get_settings(); 
        $box_bg_color       = !empty($settings['box_bg_color']) ? $settings['box_bg_color'] : 'transparent';
        $box_padding        = !empty($settings['box_padding']) ? $settings['box_padding'] : '20';
        $box_border_radius  = !empty($settings['box_border_radius']) ? $settings['box_border_radius'] : '0'; 
        $avater_radius      = !empty($settings['avater_radius']) ? $settings['avater_radius'] : '0';
        $title_size         = !empty($settings['title_size']) ? $settings['title_size'] : '22';
        $title_mb           = !empty($settings['title_mb']) ? $settings['title_mb'] : '8';
        $title_color        = !empty($settings['title_color']) ? $settings['title_color'] : '#000000';
        $designation_font_size  = !empty($settings['designation_font_size']) ? $settings['designation_font_size'] : '14';
        $designation_mb     = !empty($settings['designation_mb']) ? $settings['designation_mb'] : '5';
        $designation_color  = !empty($settings['designation_color']) ? $settings['designation_color'] : '#666666';
        $description_font_size = !empty($settings['description_font_size']) ? $settings['description_font_size'] : '16';
        $description_mb     = !empty($settings['description_mb']) ? $settings['description_mb'] : '15';
        $description_color  = !empty($settings['description_color']) ? $settings['description_color'] : '#666';
        $social_font_size  = !empty($settings['social_font_size']) ? $settings['social_font_size'] : '14';
        $social_space_between  = !empty($settings['social_space_between']) ? $settings['social_space_between'] : '5';
        $social_width       = !empty($settings['social_width']) ? $settings['social_width'] : '25';
        $social_height      = !empty($settings['social_height']) ? $settings['social_height'] : '25';
        $social_border_radius = !empty($settings['social_border_radius']) ? $settings['social_border_radius'] : '0';
        $extra_bio_font_size = !empty($settings['extra_bio_font_size']) ? $settings['extra_bio_font_size'] : '14';
        $extra_bio_padding = !empty($settings['extra_bio_padding']) ? $settings['extra_bio_padding'] : '20';
        $extra_bio_space_between = !empty($settings['extra_bio_space_between']) ? $settings['extra_bio_space_between'] : '5';
        $extra_bio_border_radius = !empty($settings['extra_bio_border_radius']) ? $settings['extra_bio_border_radius'] : '36';
       
        $primary_color   = authorsy_get_option('primary_color');
        $secondary_color = authorsy_get_option('secondary_color');
        $ea_custom_css = authorsy_get_option('ea_custom_css');
        if(is_single()){
            $custom_css.= $ea_custom_css;
        }
     
        $custom_css .= "

        :root { 
            --ea-color-main: $primary_color;  
        } 
        .ea-author-box-item {
            background-color: $box_bg_color;
            padding: {$box_padding}px;
            border-radius: {$box_border_radius}px; 
        }
       
        .ea-author-img img { 
            border-radius: {$avater_radius}px;
        }
        .ea-author-box .ea-author-name {
            font-size: {$title_size}px !important;
            margin-bottom: {$title_mb}px !important;
        }
        .ea-author-box .ea-author-name a,
        .ea-author-name{ 
            color: $title_color !important;
        }
         .ea-author-designation {
            font-size: {$designation_font_size}px !important;
            margin-bottom: {$designation_mb}px !important;
            color: $designation_color !important;
        }
        .ea-author-box .ea-author-description {
            font-size: {$description_font_size}px !important;
            margin-bottom: {$description_mb}px !important;
            color: $description_color !important;
        }
        .ea-author-box .ea-author-socials li a {
            font-size: {$social_font_size}px !important;
            width: {$social_width}px !important;
            height: {$social_height}px !important;
            line-height: {$social_height}px !important;
            border-radius: {$social_border_radius}px !important;
           

        }
        .ea-author-box .ea-author-socials{
            gap: {$social_space_between}px !important;
        }
        .ea-author-extra-bio li a {
            font-size: {$extra_bio_font_size}px !important;
            padding: 6px {$extra_bio_padding}px !important;
            border-radius: {$extra_bio_border_radius}px !important;
        }
        .ea-author-extra-bio{
            gap: {$extra_bio_space_between}px !important;
        }

        "; 

        // add inline css.
        wp_register_style('authorsy-custom-css', false);
        wp_enqueue_style('authorsy-custom-css');
        wp_add_inline_style('authorsy-custom-css', $custom_css);
    }
}
