<?php
/**
 * Api Author    
 *
 * @package Authorsy
 */
namespace Authorsy\Core\Authors;
defined( 'ABSPATH' ) || exit;

use Authorsy\Base\Api;
use Authorsy\Core\Authors\Author;
use Authorsy\Utils\Singleton;
use WP_Error;
use WP_HTTP_Response;
use WP_User_Query;

/**
 * Class Api_Author
 */
class Api_Author extends Api {
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
    protected $rest_base = 'author';

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
                    'callback'            => [ $this, 'get_items' ],
                    'permission_callback' => function () {
                        // Require administrator privileges to access sensitive author data
                        return current_user_can( 'manage_options' );
                    },
                ],
                [
                    'methods'             => \WP_REST_Server::CREATABLE,
                    'callback'            => [ $this, 'create_item' ],
                    'permission_callback' => function () {
                        return current_user_can( 'manage_options' );
                    },
                ],
                [
                    'methods'             => \WP_REST_Server::DELETABLE,
                    'callback'            => [ $this, 'bulk_delete' ],
                    'permission_callback' => function () {
                        return current_user_can( 'manage_options' );
                    },
                ],
            ]
        );
        register_rest_route(
            $this->namespace, $this->rest_base. '/frontend', [ 
                [
                    'methods'             => \WP_REST_Server::READABLE,
                    'callback'            => [ $this, 'get_users_data' ],
                    'permission_callback' => function () {
                        return true;
                    },
                ], 
            ]
        );

        /**
         * Register route
         *
         * @var void
         */
        register_rest_route(
            $this->namespace, '/' . $this->rest_base . '/(?P<author_id>[\d]+)', [
                [
                    'methods'             => \WP_REST_Server::READABLE,
                    'callback'            => [ $this, 'get_item' ],
                    'permission_callback' => function () {
                        // Require administrator privileges to access sensitive author data
                        return current_user_can( 'manage_options' );
                    },
                ],
                [
                    'methods'             => \WP_REST_Server::EDITABLE,
                    'callback'            => [ $this, 'update_item' ],
                    'permission_callback' => function () {
                        return current_user_can( 'manage_options' );
                    },
                ],
                [
                    'methods'             => \WP_REST_Server::EDITABLE,
                    'callback'            => [ $this, 'duplicate_item' ],
                    'permission_callback' => function () {
                        return current_user_can( 'manage_options' );
                    },
                ],
                [
                    'methods'             => \WP_REST_Server::DELETABLE,
                    'callback'            => [ $this, 'delete_item' ],
                    'permission_callback' => function () {
                        return current_user_can( 'manage_options' );
                    },
                ],
            ]
        );
        /**
         * Register route
         *
         * @var void
         */
        register_rest_route(
            $this->namespace, '/' . $this->rest_base . '/duplicate/(?P<author_id>[\d]+)', [ 
                [
                    'methods'             => \WP_REST_Server::EDITABLE,
                    'callback'            => [ $this, 'duplicate_item' ],
                    'permission_callback' => function () {
                        return current_user_can( 'manage_options' );
                    },
                ],
             
            ]
        );

        register_rest_route(
            $this->namespace, $this->rest_base . '/search', [
                [
                    'methods'             => \WP_REST_Server::READABLE,
                    'callback'            => [ $this, 'search_items' ],
                    'permission_callback' => function () {
                        return current_user_can( 'edit_posts' );
                    },
                ],
            ]
        );
 
    }
    

    /**
     * Get all usesrs
     *
     * @param   WP_Rest_Request  $request
     *
     * @return  JSON
     */
    public function get_items( $request ) {
        $per_page = ! empty( $request['per_page'] ) ? intval( $request['per_page'] ) : 20;
        $paged    = ! empty( $request['paged'] ) ? intval( $request['paged'] ) : 1;
        $user_ids = ! empty( $request['user_ids'] ) ? $request['user_ids'] : [];

        $author = Author::all(
            [
                'number' => $per_page,
                'paged'  => $paged,
                'include' => $user_ids,
            ]
        );

        $items = [];

        foreach ( $author['items'] as $item ) {
            $items[] = $this->prepare_item( $item->ID );
        }
 

        $data = [
            'success' => 1,
            'data'    => [
                'total' => $author['total'],
                'items' => $items,
            ],
        ];

        return rest_ensure_response( $data );
    }

    /**
     * Get all useres for frontend
     *
     * @param   WP_Rest_Request  $request
     *
     * @return  JSON
     */
    public function get_users_data( $request ) {
 
        $user_ids = ! empty( $request['user_ids'] ) ? array_map( 'intval', $request['user_ids']) : [];
  
        $author = Author::all(
            [ 
                'include' => $user_ids,
                'orderby' => 'include'
            ]
        );

        $items = [];

        foreach ( $author['items'] as $item ) {
            $items[] = $this->prepare_frontend_data( $item->ID );
        }
 

        $data = [
            'success' => 1,
            'data'    => [
                'total' => $author['total'],
                'items' => $items,
            ],
        ];

        return rest_ensure_response( $data );
    }



    /**
     * Get single author
     *
     * @param   WP_Rest_Requesr  $request
     *
     * @return  JSON Single author data
     */
    public function get_item( $request ) {
        $author_id = (int) $request['author_id'];
        $author    = new Author( $author_id );

        if ( ! $author->is_author() ) {
            return [
                'status_code' => 404,
                'message'     => __( 'Invalid user id.', 'authorsy' ),
                'data'        => [],
            ];
        }

        $response = [
            'status_code' => 200,
            'data'        => $this->prepare_item( $author ),
        ];

        return rest_ensure_response( $response );
    }
 
    /**
     * Create author
     *
     * @param   WP_Rest_Request  $request
     *
     * @return  JSON | WP_Error
     */
    public function create_item( $request ) {
        return $this->save_author( $request );
    }

    /**
     * Update Author
     *
     * @param   WP_Rest_Request  $request
     *
     * @return  JSON | WP_Error
     */
    public function update_item( $request ) {
        $author_id = (int) $request['author_id'];
        $author    = new Author( $author_id );

        if ( ! $author->is_author() ) {
            $data = [
                'status_code' => 404,
                'message'     => __( 'Invalid user id.', 'authorsy' ),
                'data'        => [],
            ];

            return new WP_HTTP_Response( $data, 404 );
        }

        return $this->save_author( $request, $author_id );
    }

    /**
     * Delete Author
     *
     * @param   WP_Rest_Request  $request
     *
     * @return  JSON
     */
    public function delete_item( $request ) {
        $author_id = (int) $request['author_id'];
        $author    = new Author( $author_id );

        if ( ! $author->is_author() || is_super_admin($author_id)) {
            $data = [
                'status_code' => 404,
                'message'     => __( 'Invalid user id.', 'authorsy' ),
                'data'        => [],
            ];

            return new WP_HTTP_Response( $data, 404 );
        }

        $author->delete();

        $response = [
            'status_code' => 200,
            'message'     => __( 'Successfully deleted author', 'authorsy' ),
            'data'        => [],
        ];

        return rest_ensure_response( $response );
    }

    /**
     * Delete multiples
     *
     * @param   WP_Rest_Request  $request
     *
     * @return JSON
     */
    public function bulk_delete( $request ) {
        $authors = json_decode( $request->get_body(), true );
    
        foreach ( $authors as $author ) {
            $author = new Author( $author );
    
            // Skip administrators
            if ( is_super_admin( $author->get_id() ) ) {
                continue; // Skip to the next iteration of the loop
            }
    
            // Check if it's a valid author to delete
            if ( ! $author->is_author() ) {
                $data = [
                    'success' => 1,
                    'status'  => 404,
                    'message' => __( 'Invalid user id.', 'authorsy' ),
                    'data'    => [],
                ];
    
                return new WP_HTTP_Response( $data, 404 );
            }
    
            // Delete the author
            $author->delete();
        }
    
        return [
            'success' => 1,
            'status'  => 200,
            'message' => __( 'Successfully deleted author', 'authorsy' ),
            'data'    => [
                'items' => $authors,
            ],
        ];
    }

      

    /**
     * Save author
     *
     * @param   WP_Rest_Request  $request
     * @param   integer  $id       [$id description]
     *
     * @return  JSON | WP_Error
     */
    public function save_author( $request, $id = 0 ) {
        $data = json_decode( $request->get_body(), true ); 
        $this->verify_nonce( $request );

        $first_name = ! empty( $data['first_name'] ) ? sanitize_text_field( $data['first_name'] ) : '';
        $last_name  = ! empty( $data['last_name'] ) ? sanitize_text_field( $data['last_name'] ) : '';
        $email      = ! empty( $data['user_email'] ) ? $data['user_email'] : '';
        $designation    = ! empty( $data['designation'] ) ? $data['designation'] : '';
        $phone      = ! empty( $data['phone'] ) ? $data['phone'] : '';
        $role       = ! empty( $data['role'] ) ? $data['role'] : '';
        $description = ! empty( $data['description'] ) ? $data['description'] : '';
        $social     = ! empty( $data['social'] ) ? $data['social'] : [];
     
 
        $image      = ! empty( $data['image'] ) ? intval( $data['image'] ) : '';
        $image_id   = ! empty( $data['image_id'] ) ? intval( $data['image_id'] ) : '';
     
        $password   = ! empty( $data['password'] ) ? sanitize_text_field( $data['password'] ) : '';
        $action     = $id ? 'updated' : 'created';

        // Validate input data.
        $validate = $this->validate(
            $data, [
                'first_name',
                'last_name',
                'user_email',
                'role',
            ]
        );

        if ( is_wp_error( $validate ) ) {
            $data = [
                'success'     => 0,
                'status_code' => 409,
                'message'     => $validate->get_error_messages(),
                'data'        => [],
            ];

            return new WP_HTTP_Response( $data, 409 );
        }

        // Save author data.
        $author = new Author( $id );

        if ( 'updated' == $action ) {
            if ( ! $image ) {
                $image = $author->get_image();
            }
        }

        $arguments = [
            'first_name' => $first_name,
            'last_name'  => $last_name,
            'user_email' => $email,
            'user_login' => $this->generate_username( $email ),
            'phone'      => $phone,
            'image'      => $image, 
            'user_pass'  => $password,
            'role'       => $role,
            'description'=> $description,
            'social'     => $social, 
            'designation'    => $designation ,
            'image_id'   => $image_id,
            
        ];

        $args = apply_filters( 'insert_authorsy_author_meta', $arguments, $data, $author );

        if ( $id ) {
           $author_id = $author->update( $args );
        } else {
            $author_id = $author->create( $args );
        }

        if ( is_wp_error( $author_id ) ) {
            return [
                'success' => 0,
                'status'  => 409,
                'message' => $validate->get_error_message(),
                'data'    => [],
            ];
        }
        // Prepare for response.
        $item = $this->prepare_item( $author );

        $data = [
            'success' => 1,
            'status'  => 200,
            /* translators: Action */
            'message' => sprintf( __( 'Successfully %s author', 'authorsy' ), $action ),
            'data'    => $item,
        ];

        return rest_ensure_response( $data );
    }

     /**
     * Duplicate Author
     *
     * @param WP_Rest_Request $request
     *
     * @return JSON | WP_Error
     */
    public function duplicate_item($request) {
        $author_id = (int) $request['author_id'];
        $author = new Author($author_id);
    
        if (!$author->is_author()) {
            $data = [
                'status_code' => 404,
                'message'     => __('Invalid user id.', 'authorsy'),
                'data'        => [],
            ];
    
            return new WP_HTTP_Response($data, 404);
        }
    
        // Get the data of the existing author
        $author_data = $this->prepare_item($author); 
    
        // Create a duplicate author with a unique username
        $duplicate_author_data = $author_data; 
        unset($duplicate_author_data['id']);
        $duplicate_author_data['user_login'] = $this->generate_username($author_data['user_email']);
        $duplicate_author_data['user_email'] = $duplicate_author_data['user_name'].'@gmail.com';
        
        
        $duplicate_author_id = $author->create($duplicate_author_data); 
    
        if (is_wp_error($duplicate_author_id)) {
            return [
                'success' => 0,
                'status'  => 409,
                'message' => __('Failed to duplicate author', 'authorsy') . ': ',
                'data'    => [],
            ];
        }
    
        // Prepare for response.
        $duplicate_author = new Author($duplicate_author_id);
        $item = $this->prepare_item($duplicate_author);
    
        $data = [
            'success' => 1,
            'status'  => 200,
            'message' => __('Successfully duplicated author', 'authorsy'),
            'data'    => $item,
        ];
    
        return rest_ensure_response($data);
    }

    /**
     * Generate username from email
     *
     * @param   string  $email
     *
     * @return  string
     */
    public function generate_username( $email ) {
        $username = strtok( $email, '@' );

        if ( username_exists( $username ) ) {
            $username = $username . wp_rand( 10, 100 );
        }

        return $username;
    }

    /**
     * Prepare item
     *
     * @param   integer | author  $author_id  Author Id
     *
     * @return  array Author data
     */
    public function prepare_item( $author ) {
        $author = new Author( $author );

        return $author->get_data();
    }
    /**
     * Prepare item
     *
     * @param   integer | author  $author_id  Author Id
     *
     * @return  array Author data
     */
    public function prepare_frontend_data( $author ) {
        $author = new Author( $author );

        return $author->get_frontend_data();
    }

    /**
     * Search users
     *
     * @return JSON
     */
    public function search_items( $request ) {

        // Prepare search args.
        $per_page = ! empty( $request['per_page'] ) ? intval( $request['per_page'] ) : 20;
        $paged    = ! empty( $request['paged'] ) ? intval( $request['paged'] ) : 1;
        $search   = ! empty( $request['search'] ) ? sanitize_text_field( $request['search'] ) : '';

        // Get search.
        $users = new WP_User_Query(
            array(
                'roles'   => authorsy_get_author_roles(),
                'number' => $per_page,
                'paged'  => $paged,

                // @codingStandardsIgnoreStart
                'meta_query' => array(
                    'relation' => 'OR',
                    array(
                        'key'     => 'first_name',
                        'value'   => $search,
                        'compare' => 'LIKE',
                    ),
                    array(
                        'key'     => 'last_name',
                        'value'   => $search,
                        'compare' => 'LIKE',
                    ),
                    array(
                        'key'     => 'email',
                        'value'   => $search,
                        'compare' => 'LIKE',
                    ), 
                ),
                // @codingStandardsIgnoreEnd
            )
        );

        // Prepare items for response.
        $items = [];

        foreach ( $users->get_results() as $item ) {
            $items[] = $this->prepare_item( $item->ID );
        }

        $data = [
            'success' => 1,
            'status'  => 200,
            'data'    => [
                'total' => $users->get_total(),
                'items' => $items,
            ],
        ];

        return rest_ensure_response( $data );
    }
 


}
