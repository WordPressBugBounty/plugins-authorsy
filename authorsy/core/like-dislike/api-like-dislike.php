<?php
/**
 * Api Author    
 *
 * @package Authorsy
 */
namespace Authorsy\Core\Like_Dislike;
defined( 'ABSPATH' ) || exit;

use Authorsy\Base\Api;
use Authorsy\Utils\Singleton;
use Error;
use WP_Error;
use WP_HTTP_Response;
use WP_REST_Server; // Add this line to fix the reference to WP_REST_Server

/**
 * Class Api_Like_Dislike
 *
 * @package Authorsy\Core\Like_Dislike
 */
class Api_Like_Dislike extends Api {
    use Singleton;

    /**
     * Store namespace
     *
     * @var string
     */
    protected $namespace = 'authorsy/v1';

    /**
     * Store rest base
     *
     * @var string
     */
    protected $rest_base = 'like-dislike'; 
    
    private $already_liked = 0; 

    /**
     * Register rest route
     *
     * @return  void
     */
    public function register_routes() {
        /**
         * Register route
         *
         * @var void
         */
        register_rest_route(
            $this->namespace,
            '/' . $this->rest_base . '/(?P<post_id>[\d]+)',
            [
                [
                    'methods'             => WP_REST_Server::EDITABLE,
                    'callback'            => [ $this, 'update_item' ],
                    'permission_callback' => function () {
                        return true;
                    },
                ],
                [
                    'methods'             => \WP_REST_Server::READABLE,
                    'callback'            => [ $this, 'get_item' ],
                    'permission_callback' => function () {
                        return true;
                    },
                ],
            ]
        );
    }


    public function get_item( $request ) {
 
        $post_id = ! empty( $request['post_id'] ) ? (int) $request['post_id'] : 0; 

        if ( ! $post_id ) {
            $data = [
                'status_code' => 404,
                'message'     => __( 'Invalid post id.', 'authorsy' ),
                'data'        => [],
            ];

            return new WP_HTTP_Response( $data, 404 );
        }

        $authorsy_likes   = get_post_meta( $post_id, 'authorsy_likes', true );
        $authorsy_likes   = !empty( $authorsy_likes ) ? $authorsy_likes : 0;
        $authorsy_dislikes = get_post_meta( $post_id, 'authorsy_dislikes', true);
        $authorsy_dislikes = !empty( $authorsy_dislikes ) ? $authorsy_dislikes : 0;

        $authorsy_loves = get_post_meta( $post_id, 'authorsy_loves', true);
        $authorsy_loves = !empty( $authorsy_loves ) ? $authorsy_loves : 0;
        $authorsy_angry = get_post_meta( $post_id, 'authorsy_angry', true);
        $authorsy_angry = !empty( $authorsy_angry ) ? $authorsy_angry : 0;
        $already_liked = $this->get_vote_status($post_id); 

        $data = [
            'success' => 1,
            'data'    => [ 
                 "authorsy_likes" => $authorsy_likes,
                 "authorsy_dislikes" => $authorsy_dislikes, 
                 "authorsy_loves" => $authorsy_loves, 
                 "authorsy_angry" => $authorsy_angry, 
            ],
        ];

        $data['data']['voteType'] = isset($already_liked['vote_type']) ? $already_liked['vote_type'] : ''; 
        return rest_ensure_response( $data );
    }


    /**
     * Update post like dislike meta
     *
     * @param   WP_Rest_Request  $request
     *
     * @return  JSON | WP_Error
     */
    public function update_item( $request ) {
        $post_id = (int) $request['post_id'];

        if ( ! $post_id ) {
            $data = [
                'status_code' => 404,
                'message'     => __( 'Invalid post id.', 'authorsy' ),
                'data'        => [],
            ];

            return new WP_HTTP_Response( $data, 404 );
        }

        return $this->save_meta( $request, $post_id );
    } 

    /**
     * Save like dislike post meta
     *
     * @param   WP_Rest_Request  $request
     * @param   integer          $id
     *
     * @return  JSON | WP_Error
     */
    public function save_meta( $request, $post_id = 0 ) {
        $data = json_decode( $request->get_body(), true ); 
        $authorsy_likes     = ! empty( $data['authorsy_likes'] ) ? sanitize_text_field( $data['authorsy_likes'] ) : '';
        $authorsy_dislikes  = ! empty( $data['authorsy_dislikes'] ) ? sanitize_text_field( $data['authorsy_dislikes'] ) : '';
        $authorsy_loves     = ! empty( $data['authorsy_loves'] ) ? sanitize_text_field( $data['authorsy_loves'] ) : '';
        $authorsy_angry     = ! empty( $data['authorsy_angry'] ) ? sanitize_text_field( $data['authorsy_angry'] ) : '';
        $vote_type          = ! empty( $data['voteType'] ) ? sanitize_text_field( $data['voteType'] ) : '';
        $feedback            = ! empty( $data['feedback'] ) ? sanitize_text_field( $data['feedback'] ) : '';
    
        $arguments = [
            'authorsy_likes'    => $authorsy_likes,
            'authorsy_dislikes' => $authorsy_dislikes,
            'authorsy_loves'    => $authorsy_loves,
            'authorsy_angry'    => $authorsy_angry,
            'feedback'          => $feedback,
            'voteType'          => $vote_type,
         ]; 

        $item = $this->update_post_meta_data( $post_id, $arguments );
     
    
        $data = [
            'success' => 1,
            'status'  => 200,
            'data'    => $item,
        ]; 
    
        return rest_ensure_response( $data );
    }
    

    /**
     * Update post meta
     *
     * @param   int     $post_id
     * @param   array   $args
     *
     * @return  array
     */
    public function update_post_meta_data($post_id, $args) {
        $likes    = get_post_meta($post_id, 'authorsy_likes', true);
        $dislikes = get_post_meta($post_id, 'authorsy_dislikes', true);
        $loves    = get_post_meta($post_id, 'authorsy_loves', true);
        $angry    = get_post_meta($post_id, 'authorsy_angry', true);

        $likes    = !empty($likes) ? intval($likes) : 0;
        $dislikes = !empty($dislikes) ? intval($dislikes) : 0;
        $loves    = !empty($loves) ? intval($loves) : 0;
        $angry    = !empty($angry) ? intval($angry) : 0;

        $settings = authorsy_get_settings();
        $restriction = !empty($settings['likes_dislike_restriction']) ? $settings['likes_dislike_restriction'] : 'no_restriction';
        $already_liked = $this->get_vote_status($post_id);

        
   
        switch ($restriction) {
            case 'ip_restriction': 
                $this->save_ips_meta($post_id, $args);
                break; 
            case 'logged_in_user': 
                $this->save_users_meta($post_id, $args);
                break;
            case 'cookie_restriction': 
                $this->set_cookie_restriction($post_id, $args);
                break; 
        }
        
        if (!empty($already_liked) && $already_liked['status'] == 1) { 
            
            return [
                'authorsy_likes'    => $likes,
                'authorsy_dislikes' => $dislikes,
                'authorsy_loves'    => $loves,
                'authorsy_angry'    => $angry,
                'user_vote'         => 1,
                'voteType'          => $already_liked['vote_type'],
            ];
        }

        // update post meta fields
        $likes_count = $likes + intval($args['authorsy_likes']);
        $dislikes_count = $dislikes + intval($args['authorsy_dislikes']);
        $loves_count = $loves + intval($args['authorsy_loves']);
        $angry_count = $angry + intval($args['authorsy_angry']);
        update_post_meta($post_id, 'authorsy_likes', $likes_count);
        update_post_meta($post_id, 'authorsy_dislikes', $dislikes_count); 
        update_post_meta($post_id, 'authorsy_loves', $loves_count); 
        update_post_meta($post_id, 'authorsy_angry', $angry_count); 
    
        // Return the updated data as needed
        return [
            'authorsy_likes'    => $likes_count,
            'authorsy_dislikes' => $dislikes_count,
            'authorsy_loves'    => $loves_count,
            'authorsy_angry'    => $angry_count,
            'voteType'          => $args['voteType'],
        ];
    } 
    /**
     * Get the vote status of a post for the current user.
     *
     * @param int $post_id The ID of the post.
     * @return int The vote status of the post.
     */
    public function get_vote_status($post_id){
        $settings = authorsy_get_settings();
        $restriction = !empty($settings['likes_dislike_restriction']) ? $settings['likes_dislike_restriction'] : 'no_restriction';
        
        switch ($restriction) {
            case 'ip_restriction':
                return $this->check_ip_restriction($post_id);
                
            case 'cookie_restriction':
                return $this->check_cookie_restriction($post_id);
        
            case 'logged_in_user':
                return $this->get_user_vote_status($post_id);
                
            default:
                return 0;
        }
    }

      /**
     * Retrieves the vote status of a user for a specific post.
     *
     * @param int $post_id The ID of the post.
     * @return int|null The vote status of the user: 1 if the user has already voted, null otherwise.
     */
    public function get_user_vote_status($post_id){ 
        $already_liked = [];
        
        if (is_user_logged_in()) {
            $liked_users = get_post_meta($post_id, 'authorsy_users_vote', true);
            $liked_users = (empty($liked_users)) ? array() : $liked_users;
            $current_user_id = get_current_user_id();
            $already_liked = $this->get_vote_info_status($current_user_id, $liked_users, $post_id, 'authorsy_users_vote_info');
        }   
        return $already_liked;
    }

    /**
     * Check IP restriction for liking/disliking a post.
     *
     * @param int $post_id
     * @return int
     */
   public function check_ip_restriction($post_id) {
 
        $liked_ips = get_post_meta($post_id, 'authorsy_ips', true);
        $liked_ips = empty($liked_ips) ? array() : $liked_ips;
        $user_ip = $this->get_user_IP();
        $already_liked = $this->get_vote_info_status($user_ip, $liked_ips, $post_id, 'authorsy_ips_vote_info');
        return  $already_liked;
    }

    public function get_vote_info_status($user_id, $users, $post_id, $info_key){
        $already_liked = [];
        $liked_users_info = get_post_meta($post_id, $info_key, true);
        $liked_users_info = (empty($liked_users_info)) ? array() : $liked_users_info;

        if (in_array($user_id, $users)) {
            $vote_type = null;
            if(!empty( $liked_users_info)){
                $vote_type = $liked_users_info[$user_id];
                
            } 
            $already_liked['vote_type'] = $vote_type['vote_type'];
            $already_liked['status'] = 1;
        }

        return  $already_liked;
    }

    /**
     * Check cookie restriction for liking/disliking a post.
     *
     * @param int $post_id
     * @return int
     */
    function check_cookie_restriction($post_id) {
        $already_liked=[];
        if(isset($_COOKIE['authorsy_' . $post_id])) {
            $already_liked['vote_type'] = $_COOKIE['authorsy_' . $post_id];
            $already_liked['status'] = 1;
        }
        return $already_liked;
    }
      
    
    /**
     * Check cookie restriction for liking/disliking a post.
     *
     * @param int $post_id
     * @return int
     */
    function set_cookie_restriction($post_id, $args) { 
        $already_liked = $this->get_vote_status($post_id);
         
        if(!isset($already_liked['vote_type'])) {
            return setcookie('authorsy_' . $post_id, $args['voteType'], time() + 365 * 24 * 60 * 60, '/');
        }
          $liked_users_info = get_post_meta($post_id, 'authorsy_cookie_vote_info', true);
         $liked_users_info = !empty($liked_users_info) ? $liked_users_info : [];
         $current_time  = time();
        
         $liked_users_info[$current_time] = [
             'vote_type' => $args['voteType'],
             'feedback'   => $args['feedback'],
         ];
 
         update_post_meta($post_id, 'authorsy_cookie_vote_info', $liked_users_info);

        
    }
    

    /**
     * Retrieves the IP address of the user.
     *
     * @return string The IP address of the user, or an empty string if not found.
     */
    public function get_user_IP() {
        $ipHeaders = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];
    
        foreach ($ipHeaders as $header) {
            if (!empty($_SERVER[$header]) && filter_var($_SERVER[$header], FILTER_VALIDATE_IP)) {
                return $_SERVER[$header];
            }
        }
    
        return '';
    }

    /**
     * Saves the IP addresses in the post meta for the given post ID.
     *
     * @param int $post_id The ID of the post.
     * @throws Some_Exception_Class If there is an error updating the post meta.
     * @return void
     */
    public function save_ips_meta($post_id, $args) {
        $liked_ips = get_post_meta($post_id, 'authorsy_ips', true);
        $liked_ips = (!empty($liked_ips)) ? $liked_ips : array(); 

        $user_ip = $this->get_user_IP();
        $liked_users_info = get_post_meta($post_id, 'authorsy_ips_vote_info', true);
        $liked_users_info = !empty($liked_users_info) ? $liked_users_info : [];

        if (!in_array($user_ip, $liked_ips)) {
            $liked_ips[] = $user_ip; 
            
        }
        $liked_users_info[$user_ip] =  [
            'vote_type' => $args['voteType'],
            'feedback'   => $args['feedback'],
        ];
        update_post_meta($post_id, 'authorsy_ips', $liked_ips); 
        update_post_meta($post_id, 'authorsy_ips_vote_info', $liked_users_info);
         
     }

    /**
      * Saves the users meta for a given post ID.
      *
      * @param int $post_id The ID of the post.
      */
     public function save_users_meta($post_id, $args) {
        if (is_user_logged_in()) {

            $liked_users = get_post_meta($post_id, 'authorsy_users_vote', true);
            $liked_users = !empty($liked_users) ? $liked_users : [];

            $current_user_id = get_current_user_id();
            if (!in_array($current_user_id, $liked_users)) {
                $liked_users[] = $current_user_id;
            }
            $liked_users_info = get_post_meta($post_id, 'authorsy_users_vote_info', true);
            $liked_users_info = !empty($liked_users_info) ? $liked_users_info : [];
            $liked_users_info[$current_user_id] = [
                'vote_type' => $args['voteType'],
                'feedback'   => $args['feedback'],
            ];

            update_post_meta($post_id, 'authorsy_users_vote', $liked_users); 
            update_post_meta($post_id, 'authorsy_users_vote_info', $liked_users_info);
           
             
         }
     }
 
 
}
