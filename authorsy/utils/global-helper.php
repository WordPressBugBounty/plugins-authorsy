<?php
defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'authorsy_update_default_settings' ) ) {

    /**
     * Update default settings
     *
     * @return void
     */
    function authorsy_update_default_settings() {
        $settings = [ 
            'primary_color'            => '#275cde',
            'secondary_color'          => '#275cde',
            'visible_author_on'        => ['post'],
            'visible_likes_box_on'     => ['post'], 
            'enable_multi_author'      => '',
            'enable_author_on_hover'   => '',
            'box_bg_color' => 'transparent',
            'box_padding' => 20,
            'box_border_radius' => 0,
            'avater_radius' => 0,
            'title_size' => 22,
            'title_mb' => 8,
            'title_color' => '#000000',
            'designation_font_size' => 14,
            'designation_mb' => 5,
            'designation_color' => '#666666',
            'description_font_size' => 16,
            'description_mb' => 15,
            'description_color' => '#666',
            'social_font_size' => 14,
            'social_space_between' => 5,
            'social_width' => 25,
            'social_height' => 25,
            'social_border_radius' => 0,
            'extra_bio_font_size' => 14,
            'extra_bio_padding' => 20,
            'extra_bio_space_between' => 5,
            'extra_bio_border_radius' => 36,
            'extra_bio_title' => __( 'Extra Bio', 'authorsy' ),
        ];

        $settings = apply_filters( 'authorsy_default_settings', $settings );

        foreach ( $settings as $key => $value ) {
            authorsy_update_option( $key, $value );
        }
    }
}
  
if ( ! function_exists( 'authorsy_get_socials' ) ) { 
    /**
     * Get socials
     *
     * @return array
     */
    function authorsy_get_socials( $socials, $class="" ) {
        if(!empty($socials)){ 
            ?>
            <ul class="ea-author-socials <?php echo esc_attr($class); ?>"> 
                <?php  
                    foreach ($socials as $social) {  
                        $url = !empty($social['url']) ? $social['url'] : '#';
                        $title = !empty($social['title']) ? $social['title'] : '';
                        $icon = !empty($social['icon']) ? $social['icon'] : '';
                        $color = !empty($social['color']) ? $social['color'] : '';
                        $bg_color = !empty($social['bg_color']) ? $social['bg_color'] : '';
                        echo '<li><a href="'.esc_url($url).'" target="_blank" title="'.esc_attr($title).'" style="color:'.esc_attr($color).'; background:'.esc_attr($bg_color).'"><i class="ea '.esc_attr($icon).'"></i></a></li>';
                    } 
                ?>
            </ul>
        <?php  }  
    }

}
if ( ! function_exists( 'authorsy_get_author_roles' ) ) { 
    /**
     * Get author roles
     *
     * @return array
     */
    function authorsy_get_author_roles() {
        $user_roles = ["administrator","editor", "author", "authorsy-guest"];
        return $user_roles;
    }

}
 
if ( ! function_exists( 'authorsy_author_image' ) ) { 
    /**
     * Get author profile image
     *
     * @return array
     */
    function authorsy_author_image($author_info, $author_id) {
       if(!empty($author_info->get_image())){ ?>
            <div class="ea-author-img">
                <a href="<?php echo esc_url(get_author_posts_url($author_id)); ?>">
                    <img src="<?php echo esc_url($author_info->get_image()); ?>" alt="<?php echo esc_html($author_info->get_full_name()); ?>"/>
                </a>
            </div>
        <?php }  
    }

}
if ( ! function_exists( 'authorsy_author_name' ) ) { 
    /**
     * Get author name
     *
     * @return array
     */
    function authorsy_author_name($author_info, $author_id) {
     ?>
        <h3 class="ea-author-name">
            <a href="<?php echo esc_url(get_author_posts_url($author_id)); ?>">
                <?php echo esc_html($author_info->get_full_name()); ?>
            </a>
        </h3>
     <?php  
    }

}
 