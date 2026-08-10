<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Webrium\XZeroProtect\Request;
use Webrium\XZeroProtect\VisitFilter;
use Webrium\XZeroProtect\VisitInfo;
use Webrium\XZeroProtect\XZeroProtect;

class VisitFilterTest extends TestCase
{
    /** Headers the tracking tests set; cleared around every test. */
    private const VOLATILE_HEADERS = [
        'HTTP_REFERER',
        'HTTP_SEC_FETCH_DEST',
        'HTTP_X_REQUESTED_WITH',
        'HTTP_SEC_PURPOSE',
        'HTTP_PURPOSE',
        'HTTP_X_PURPOSE',
        'HTTP_X_MOZ',
    ];

    private string $rulesDir;
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->rulesDir = dirname(__DIR__) . '/rules';
        $this->tmpDir   = sys_get_temp_dir() . '/xzp_visitfilter_' . uniqid();
        mkdir($this->tmpDir, 0755, true);

        $_SERVER['REMOTE_ADDR']     = '203.0.113.10';
        $_SERVER['REQUEST_METHOD']  = 'GET';
        $_SERVER['REQUEST_URI']     = '/';
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36';
        $_GET = $_POST = $_COOKIE = [];

        $this->clearHeaders();
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->tmpDir);
        $this->clearHeaders();
    }

    private function clearHeaders(): void
    {
        foreach (self::VOLATILE_HEADERS as $header) {
            unset($_SERVER[$header]);
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private function filter(array $config = []): VisitFilter
    {
        return new VisitFilter($this->rulesDir, $config);
    }

    private function request(string $uri, string $method = 'GET'): Request
    {
        $_SERVER['REQUEST_URI']    = $uri;
        $_SERVER['REQUEST_METHOD'] = $method;

        return new Request();
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        foreach (scandir($dir) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $path = $dir . '/' . $entry;
            is_dir($path) ? $this->removeDir($path) : @unlink($path);
        }

        @rmdir($dir);
    }

    // =========================================================================
    // Request::path() — malformed URIs must not throw
    // =========================================================================

    public function test_path_returns_uri_for_malformed_double_slash(): void
    {
        $this->assertSame('//', $this->request('//')->path());
    }

    public function test_path_returns_uri_for_malformed_authority(): void
    {
        $this->assertSame('http://:80', $this->request('http://:80')->path());
    }

    public function test_path_strips_query_string(): void
    {
        $this->assertSame('/blog/post', $this->request('/blog/post?utm=x&a=1')->path());
    }

    // =========================================================================
    // Request::extension()
    // =========================================================================

    public function test_extension_of_asset(): void
    {
        $this->assertSame('woff2', $this->request('/assets/vazir.woff2')->extension());
    }

    public function test_extension_ignores_query_string(): void
    {
        $this->assertSame('css', $this->request('/build/app.css?v=8fa1')->extension());
    }

    public function test_extension_is_lowercased(): void
    {
        $this->assertSame('png', $this->request('/img/Logo.PNG')->extension());
    }

    public function test_extension_empty_for_clean_route(): void
    {
        $this->assertSame('', $this->request('/user/dashboard')->extension());
    }

    public function test_extension_empty_for_dotfile(): void
    {
        $this->assertSame('', $this->request('/.env')->extension());
    }

    public function test_extension_empty_for_trailing_dot(): void
    {
        $this->assertSame('', $this->request('/foo.')->extension());
    }

    public function test_extension_empty_for_directory_path(): void
    {
        $this->assertSame('', $this->request('/blog/')->extension());
    }

    public function test_extension_takes_last_segment_only(): void
    {
        // A dot in a parent directory must not leak into the result.
        $this->assertSame('', $this->request('/v1.2/changelog')->extension());
    }

    public function test_extension_of_double_extension(): void
    {
        $this->assertSame('map', $this->request('/build/app.js.map')->extension());
    }

    public function test_extension_with_utf8_path(): void
    {
        $this->assertSame('webp', $this->request('/مقاله/تصویر.webp')->extension());
    }

    public function test_extension_empty_for_utf8_route(): void
    {
        $this->assertSame('', $this->request('/دسته/مقاله-اول')->extension());
    }

    // =========================================================================
    // Request::header()
    // =========================================================================

    public function test_header_reads_dashed_name(): void
    {
        $_SERVER['HTTP_SEC_FETCH_DEST'] = 'document';
        $this->assertSame('document', $this->request('/')->header('Sec-Fetch-Dest'));
        unset($_SERVER['HTTP_SEC_FETCH_DEST']);
    }

    public function test_header_returns_empty_when_absent(): void
    {
        $this->assertSame('', $this->request('/')->header('X-Not-Sent'));
    }

    // =========================================================================
    // Extension filtering
    // =========================================================================

    public function test_missing_font_is_not_tracked(): void
    {
        $filter = $this->filter();

        $this->assertFalse($filter->shouldTrack($this->request('/assets/fonts/vazir.woff2')));
        $this->assertSame('extension:.woff2', $filter->lastReason());
    }

    public function test_stylesheet_and_script_are_not_tracked(): void
    {
        $filter = $this->filter();

        $this->assertFalse($filter->shouldTrack($this->request('/build/app.css')));
        $this->assertFalse($filter->shouldTrack($this->request('/build/app.js')));
    }

    public function test_uppercase_extension_is_not_tracked(): void
    {
        $this->assertFalse($this->filter()->shouldTrack($this->request('/img/Banner.PNG')));
    }

    public function test_asset_with_cache_busting_query_is_not_tracked(): void
    {
        $this->assertFalse($this->filter()->shouldTrack($this->request('/build/app.css?v=8fa1')));
    }

    public function test_real_page_is_tracked(): void
    {
        $filter = $this->filter();

        $this->assertTrue($filter->shouldTrack($this->request('/blog/how-to-build-a-cms')));
        $this->assertNull($filter->lastReason());
    }

    public function test_utf8_page_is_tracked(): void
    {
        $this->assertTrue($this->filter()->shouldTrack($this->request('/دسته/مقاله-اول')));
    }

    public function test_route_with_unlisted_extension_is_tracked(): void
    {
        // .json and .html stay trackable because apps legitimately route them.
        $this->assertTrue($this->filter()->shouldTrack($this->request('/api/report.json')));
        $this->assertTrue($this->filter()->shouldTrack($this->request('/page.html')));
    }

    public function test_malformed_uri_does_not_throw_and_is_tracked(): void
    {
        $this->assertTrue($this->filter()->shouldTrack($this->request('//')));
    }

    // =========================================================================
    // Path filtering
    // =========================================================================

    public function test_favicon_is_not_tracked(): void
    {
        $filter = $this->filter();

        $this->assertFalse($filter->shouldTrack($this->request('/favicon.ico')));
        $this->assertSame('path:/favicon.ico', $filter->lastReason());
    }

    public function test_webmanifest_route_is_not_tracked(): void
    {
        // A real application route, yet a sub-resource — extensions cannot catch it.
        $this->assertFalse($this->filter()->shouldTrack($this->request('/site.webmanifest')));
    }

    public function test_robots_and_sitemap_are_not_tracked(): void
    {
        $filter = $this->filter();

        $this->assertFalse($filter->shouldTrack($this->request('/robots.txt')));
        $this->assertFalse($filter->shouldTrack($this->request('/sitemap.xml')));
        $this->assertFalse($filter->shouldTrack($this->request('/sitemap-posts-1.xml')));
    }

    public function test_well_known_is_not_tracked(): void
    {
        $this->assertFalse($this->filter()->shouldTrack($this->request('/.well-known/acme-challenge/token')));
    }

    public function test_ignored_path_matches_case_insensitively(): void
    {
        $this->assertFalse($this->filter()->shouldTrack($this->request('/Favicon.ICO')));
    }

    public function test_ignored_path_is_a_prefix_not_a_substring(): void
    {
        // '/sitemap' must not reject a page that merely mentions it later on.
        $this->assertTrue($this->filter()->shouldTrack($this->request('/blog/sitemap-guide')));
    }

    // =========================================================================
    // Method filtering
    // =========================================================================

    public function test_post_is_not_tracked_by_default(): void
    {
        $filter = $this->filter();

        $this->assertFalse($filter->shouldTrack($this->request('/login', 'POST')));
        $this->assertSame('method:POST', $filter->lastReason());
    }

    public function test_head_and_options_are_not_tracked(): void
    {
        $filter = $this->filter();

        $this->assertFalse($filter->shouldTrack($this->request('/', 'HEAD')));
        $this->assertFalse($filter->shouldTrack($this->request('/', 'OPTIONS')));
    }

    public function test_allow_method_enables_post(): void
    {
        $filter = $this->filter()->allowMethod('post');

        $this->assertTrue($filter->shouldTrack($this->request('/login', 'POST')));
    }

    public function test_empty_method_list_accepts_any_method(): void
    {
        $filter = $this->filter(['methods' => []]);

        $this->assertTrue($filter->shouldTrack($this->request('/login', 'POST')));
        $this->assertTrue($filter->shouldTrack($this->request('/', 'DELETE')));
    }

    public function test_methods_are_normalized_to_uppercase(): void
    {
        $this->assertSame(['GET', 'POST'], $this->filter(['methods' => ['get', ' post ']])->getMethods());
    }

    // =========================================================================
    // Runtime mutation
    // =========================================================================

    public function test_add_ignored_extension_accepts_bare_and_dotted_forms(): void
    {
        $filter = $this->filter()->addIgnoredExtension('woff3')->addIgnoredExtension('.AVIFS');

        $this->assertFalse($filter->shouldTrack($this->request('/a/x.woff3')));
        $this->assertFalse($filter->shouldTrack($this->request('/a/x.avifs')));
    }

    public function test_remove_ignored_extension_restores_tracking(): void
    {
        $filter = $this->filter()->removeIgnoredExtension('svg');

        $this->assertTrue($filter->shouldTrack($this->request('/icons/logo.svg')));
        $this->assertNotContains('.svg', $filter->getIgnoredExtensions());
    }

    public function test_add_ignored_path_accepts_missing_leading_slash(): void
    {
        $filter = $this->filter()->addIgnoredPath('api/');

        $this->assertFalse($filter->shouldTrack($this->request('/api/user/profile')));
        $this->assertSame('path:/api/', $filter->lastReason());
    }

    public function test_remove_ignored_path_restores_tracking(): void
    {
        $filter = $this->filter()->removeIgnoredPath('/robots.txt');

        $this->assertTrue($filter->shouldTrack($this->request('/robots.txt')));
    }

    public function test_duplicate_entries_are_not_stored_twice(): void
    {
        $filter = $this->filter();
        $before = count($filter->getIgnoredExtensions());

        $filter->addIgnoredExtension('.css')->addIgnoredExtension('css')->addIgnoredExtension('CSS');

        $this->assertCount($before, $filter->getIgnoredExtensions());
    }

    public function test_blank_entries_are_ignored(): void
    {
        $filter = $this->filter();
        $before = count($filter->getIgnoredPaths());

        $filter->addIgnoredPath('')->addIgnoredPath('   ')->addIgnoredExtension('.');

        $this->assertCount($before, $filter->getIgnoredPaths());
        $this->assertNotContains('.', $filter->getIgnoredExtensions());
    }

    // =========================================================================
    // Config
    // =========================================================================

    public function test_config_extensions_extend_the_defaults(): void
    {
        $filter = $this->filter(['ignore_extensions' => ['.woff3']]);

        $this->assertFalse($filter->shouldTrack($this->request('/a/x.woff3')));
        $this->assertFalse($filter->shouldTrack($this->request('/a/x.css')), 'defaults must survive');
    }

    public function test_config_paths_extend_the_defaults(): void
    {
        $filter = $this->filter(['ignore_paths' => ['/api']]);

        $this->assertFalse($filter->shouldTrack($this->request('/api/cart')));
        $this->assertFalse($filter->shouldTrack($this->request('/favicon.ico')), 'defaults must survive');
    }

    public function test_missing_rules_file_falls_back_to_the_packaged_defaults(): void
    {
        // A custom 'rules_path' created before this rule set existed must keep
        // working instead of fataling on a missing require.
        $customRules = $this->tmpDir . '/rules';
        mkdir($customRules, 0755, true);

        $filter = new VisitFilter($customRules);

        $this->assertFalse($filter->shouldTrack($this->request('/assets/vazir.woff2')));
        $this->assertTrue($filter->shouldTrack($this->request('/blog/42')));
    }

    public function test_custom_rules_file_replaces_the_packaged_defaults(): void
    {
        $customRules = $this->tmpDir . '/rules';
        mkdir($customRules, 0755, true);
        file_put_contents(
            $customRules . '/ignore_tracking.php',
            '<?php return ["extensions" => [".zzz"], "paths" => []];'
        );

        $filter = new VisitFilter($customRules);

        $this->assertFalse($filter->shouldTrack($this->request('/a/x.zzz')));
        $this->assertTrue($filter->shouldTrack($this->request('/build/app.css')));
    }

    public function test_disabled_filter_tracks_everything(): void
    {
        $filter = $this->filter(['filter' => false]);

        $this->assertTrue($filter->shouldTrack($this->request('/build/app.css')));
        $this->assertTrue($filter->shouldTrack($this->request('/login', 'POST')));
        $this->assertNull($filter->lastReason());
    }

    public function test_filter_can_be_toggled_at_runtime(): void
    {
        $filter = $this->filter();

        $filter->disable();
        $this->assertTrue($filter->shouldTrack($this->request('/build/app.css')));

        $filter->enable();
        $this->assertFalse($filter->shouldTrack($this->request('/build/app.css')));
    }

    // =========================================================================
    // Custom filters
    // =========================================================================

    public function test_custom_filter_can_reject(): void
    {
        $filter = $this->filter()->addFilter('no-preview', fn(Request $r) => !str_starts_with($r->path(), '/preview'));

        $this->assertFalse($filter->shouldTrack($this->request('/preview/42')));
        $this->assertSame('filter:no-preview', $filter->lastReason());
        $this->assertTrue($filter->shouldTrack($this->request('/blog/42')));
    }

    public function test_custom_filter_receives_the_request(): void
    {
        $seen = null;
        $filter = $this->filter()->addFilter('capture', function (Request $r) use (&$seen) {
            $seen = $r->path();
            return true;
        });

        $filter->shouldTrack($this->request('/captured'));

        $this->assertSame('/captured', $seen);
    }

    public function test_custom_filter_can_be_removed(): void
    {
        $filter = $this->filter()->addFilter('block-all', fn() => false);
        $this->assertFalse($filter->shouldTrack($this->request('/blog')));

        $filter->removeFilter('block-all');
        $this->assertTrue($filter->shouldTrack($this->request('/blog')));
        $this->assertFalse($filter->hasFilter('block-all'));
    }

    public function test_throwing_custom_filter_does_not_break_the_request(): void
    {
        $filter = $this->filter()->addFilter('broken', function () {
            throw new \RuntimeException('filter blew up');
        });

        $this->assertTrue($filter->shouldTrack($this->request('/blog/42')));
    }

    public function test_throwing_custom_filter_does_not_skip_later_filters(): void
    {
        $filter = $this->filter()
            ->addFilter('broken', fn() => throw new \RuntimeException('boom'))
            ->addFilter('reject', fn() => false);

        $this->assertFalse($filter->shouldTrack($this->request('/blog/42')));
        $this->assertSame('filter:reject', $filter->lastReason());
    }

    public function test_non_boolean_filter_return_keeps_the_visit(): void
    {
        // Only an explicit false discards a visit; a sloppy null must not.
        $filter = $this->filter()->addFilter('sloppy', fn() => null);

        $this->assertTrue($filter->shouldTrack($this->request('/blog/42')));
    }

    public function test_last_reason_resets_between_calls(): void
    {
        $filter = $this->filter();

        $filter->shouldTrack($this->request('/build/app.css'));
        $this->assertNotNull($filter->lastReason());

        $filter->shouldTrack($this->request('/blog/42'));
        $this->assertNull($filter->lastReason());
    }

    // =========================================================================
    // Sec-Fetch-Dest
    // =========================================================================

    public function test_document_navigation_is_tracked(): void
    {
        $_SERVER['HTTP_SEC_FETCH_DEST'] = 'document';

        $this->assertTrue($this->filter()->shouldTrack($this->request('/blog/42')));
    }

    /**
     * @dataProvider subResourceDestinations
     */
    public function test_sub_resource_destination_is_not_tracked(string $dest): void
    {
        $_SERVER['HTTP_SEC_FETCH_DEST'] = $dest;
        $filter = $this->filter();

        $this->assertFalse($filter->shouldTrack($this->request('/blog/42')));
        $this->assertSame('dest:' . $dest, $filter->lastReason());
    }

    public static function subResourceDestinations(): array
    {
        return [
            ['font'], ['image'], ['style'], ['script'], ['empty'],
            ['manifest'], ['audio'], ['video'], ['track'], ['object'],
            ['iframe'], ['frame'], ['worker'], ['serviceworker'], ['report'],
        ];
    }

    public function test_extensionless_asset_route_is_caught_by_the_header(): void
    {
        // A CAPTCHA image served from a clean route: no extension to match on,
        // yet the browser states plainly that it is not a page.
        $_SERVER['HTTP_SEC_FETCH_DEST'] = 'image';

        $this->assertFalse($this->filter()->shouldTrack($this->request('/captcha')));
    }

    public function test_absent_header_falls_back_to_the_path_and_extension_lists(): void
    {
        $filter = $this->filter();

        $this->assertFalse($filter->shouldTrack($this->request('/assets/vazir.woff2')));
        $this->assertSame('extension:.woff2', $filter->lastReason());
        $this->assertTrue($filter->shouldTrack($this->request('/blog/42')));
    }

    public function test_unknown_destination_value_is_not_tracked(): void
    {
        $_SERVER['HTTP_SEC_FETCH_DEST'] = 'somethingnew';

        $this->assertFalse($this->filter()->shouldTrack($this->request('/blog/42')));
    }

    public function test_destination_match_is_case_insensitive(): void
    {
        $_SERVER['HTTP_SEC_FETCH_DEST'] = 'DOCUMENT';

        $this->assertTrue($this->filter()->shouldTrack($this->request('/blog/42')));
    }

    public function test_destination_value_is_trimmed(): void
    {
        $_SERVER['HTTP_SEC_FETCH_DEST'] = '  document  ';

        $this->assertTrue($this->filter()->shouldTrack($this->request('/blog/42')));
    }

    public function test_document_navigation_does_not_override_ignored_paths(): void
    {
        // Typing /robots.txt in the address bar is a document navigation, but
        // an explicit ignore rule must still win.
        $_SERVER['HTTP_SEC_FETCH_DEST'] = 'document';
        $filter = $this->filter();

        $this->assertFalse($filter->shouldTrack($this->request('/robots.txt')));
        $this->assertSame('path:/robots.txt', $filter->lastReason());
    }

    public function test_document_navigation_does_not_override_ignored_extensions(): void
    {
        $_SERVER['HTTP_SEC_FETCH_DEST'] = 'document';

        $this->assertFalse($this->filter()->shouldTrack($this->request('/build/app.css')));
    }

    public function test_document_navigation_does_not_override_custom_filters(): void
    {
        $_SERVER['HTTP_SEC_FETCH_DEST'] = 'document';
        $filter = $this->filter()->addFilter('reject', fn() => false);

        $this->assertFalse($filter->shouldTrack($this->request('/blog/42')));
    }

    public function test_sec_fetch_dest_can_be_disabled(): void
    {
        $_SERVER['HTTP_SEC_FETCH_DEST'] = 'image';

        $this->assertTrue($this->filter(['use_sec_fetch_dest' => false])->shouldTrack($this->request('/blog/42')));
        $this->assertTrue($this->filter()->useSecFetchDest(false)->shouldTrack($this->request('/blog/42')));
    }

    public function test_tracked_destinations_are_configurable(): void
    {
        $_SERVER['HTTP_SEC_FETCH_DEST'] = 'iframe';

        $this->assertTrue($this->filter(['track_dest' => ['document', 'iframe']])->shouldTrack($this->request('/embed/42')));
        $this->assertTrue($this->filter()->addTrackedDest('IFRAME')->shouldTrack($this->request('/embed/42')));
        $this->assertSame(['document'], $this->filter()->getTrackedDest());
    }

    public function test_empty_tracked_destination_list_rejects_every_header(): void
    {
        $_SERVER['HTTP_SEC_FETCH_DEST'] = 'document';

        $this->assertFalse($this->filter(['track_dest' => []])->shouldTrack($this->request('/blog/42')));
    }

    // =========================================================================
    // AJAX
    // =========================================================================

    public function test_xhr_is_not_tracked(): void
    {
        $_SERVER['HTTP_X_REQUESTED_WITH'] = 'XMLHttpRequest';
        $filter = $this->filter();

        $this->assertFalse($filter->shouldTrack($this->request('/api/cart')));
        $this->assertSame('ajax', $filter->lastReason());
    }

    public function test_xhr_header_match_is_case_insensitive(): void
    {
        $_SERVER['HTTP_X_REQUESTED_WITH'] = 'xmlhttprequest';

        $this->assertFalse($this->filter()->shouldTrack($this->request('/api/cart')));
    }

    public function test_unrelated_requested_with_value_is_tracked(): void
    {
        $_SERVER['HTTP_X_REQUESTED_WITH'] = 'com.example.app';

        $this->assertTrue($this->filter()->shouldTrack($this->request('/blog/42')));
    }

    public function test_ajax_filtering_can_be_disabled(): void
    {
        $_SERVER['HTTP_X_REQUESTED_WITH'] = 'XMLHttpRequest';

        $this->assertTrue($this->filter(['ignore_ajax' => false])->shouldTrack($this->request('/blog/42')));
        $this->assertTrue($this->filter()->ignoreAjax(false)->shouldTrack($this->request('/blog/42')));
    }

    // =========================================================================
    // Prefetch / prerender
    // =========================================================================

    /**
     * @dataProvider prefetchHeaders
     */
    public function test_speculative_load_is_not_tracked(string $header, string $value): void
    {
        $_SERVER[$header] = $value;
        $filter = $this->filter();

        $this->assertFalse($filter->shouldTrack($this->request('/blog/42')));
        $this->assertSame('prefetch', $filter->lastReason());
    }

    public static function prefetchHeaders(): array
    {
        return [
            'chrome sec-purpose'   => ['HTTP_SEC_PURPOSE', 'prefetch'],
            'chrome compound'      => ['HTTP_SEC_PURPOSE', 'prefetch;prerender'],
            'chrome prerender'     => ['HTTP_SEC_PURPOSE', 'prerender'],
            'legacy purpose'       => ['HTTP_PURPOSE', 'prefetch'],
            'firefox x-moz'        => ['HTTP_X_MOZ', 'prefetch'],
            'firefox prerender'    => ['HTTP_X_MOZ', 'prerender'],
            'safari link preview'  => ['HTTP_X_PURPOSE', 'preview'],
            'uppercase value'      => ['HTTP_SEC_PURPOSE', 'PREFETCH'],
        ];
    }

    public function test_unrelated_purpose_value_is_tracked(): void
    {
        $_SERVER['HTTP_PURPOSE'] = 'transcode';

        $this->assertTrue($this->filter()->shouldTrack($this->request('/blog/42')));
    }

    public function test_prefetch_filtering_can_be_disabled(): void
    {
        $_SERVER['HTTP_SEC_PURPOSE'] = 'prefetch';

        $this->assertTrue($this->filter(['ignore_prefetch' => false])->shouldTrack($this->request('/blog/42')));
        $this->assertTrue($this->filter()->ignorePrefetch(false)->shouldTrack($this->request('/blog/42')));
    }

    public function test_prefetch_is_reported_before_destination(): void
    {
        // A prefetched navigation still carries 'Sec-Fetch-Dest: document'.
        $_SERVER['HTTP_SEC_PURPOSE']    = 'prefetch';
        $_SERVER['HTTP_SEC_FETCH_DEST'] = 'document';
        $filter = $this->filter();

        $this->assertFalse($filter->shouldTrack($this->request('/blog/42')));
        $this->assertSame('prefetch', $filter->lastReason());
    }

    // =========================================================================
    // Request header accessors
    // =========================================================================

    public function test_sec_fetch_dest_accessor(): void
    {
        $_SERVER['HTTP_SEC_FETCH_DEST'] = 'Font';
        $this->assertSame('font', $this->request('/')->secFetchDest());

        unset($_SERVER['HTTP_SEC_FETCH_DEST']);
        $this->assertSame('', $this->request('/')->secFetchDest());
    }

    public function test_is_ajax_accessor(): void
    {
        $this->assertFalse($this->request('/')->isAjax());

        $_SERVER['HTTP_X_REQUESTED_WITH'] = ' XMLHttpRequest ';
        $this->assertTrue($this->request('/')->isAjax());
    }

    public function test_is_prefetch_accessor(): void
    {
        $this->assertFalse($this->request('/')->isPrefetch());

        $_SERVER['HTTP_SEC_PURPOSE'] = 'prefetch';
        $this->assertTrue($this->request('/')->isPrefetch());
    }

    public function test_disabled_filter_ignores_header_signals(): void
    {
        $_SERVER['HTTP_SEC_FETCH_DEST']   = 'font';
        $_SERVER['HTTP_X_REQUESTED_WITH'] = 'XMLHttpRequest';
        $_SERVER['HTTP_SEC_PURPOSE']      = 'prefetch';

        $this->assertTrue($this->filter(['filter' => false])->shouldTrack($this->request('/x.woff2')));
    }

    // =========================================================================
    // Integration with XZeroProtect::run()
    // =========================================================================

    public function test_firewall_exposes_the_visit_filter(): void
    {
        $firewall = XZeroProtect::init(['storage_path' => $this->tmpDir]);

        $this->assertInstanceOf(VisitFilter::class, $firewall->visits);
    }

    public function test_run_does_not_track_a_missing_asset(): void
    {
        $recorded = [];
        $firewall = XZeroProtect::init(['storage_path' => $this->tmpDir]);
        $firewall->enableTracking(function (VisitInfo $v) use (&$recorded) {
            $recorded[] = $v->path;
        });

        $this->request('/assets/fonts/vazir.woff2');
        $firewall->run();

        $this->assertSame([], $recorded);
    }

    public function test_run_tracks_a_real_page(): void
    {
        $recorded = [];
        $firewall = XZeroProtect::init(['storage_path' => $this->tmpDir]);
        $firewall->enableTracking(function (VisitInfo $v) use (&$recorded) {
            $recorded[] = $v->path;
        });

        $this->request('/blog/how-to-build-a-cms');
        $firewall->run();

        $this->assertSame(['/blog/how-to-build-a-cms'], $recorded);
    }

    public function test_run_does_not_track_a_prefetched_page(): void
    {
        $recorded = [];
        $firewall = XZeroProtect::init(['storage_path' => $this->tmpDir]);
        $firewall->enableTracking(function (VisitInfo $v) use (&$recorded) {
            $recorded[] = $v->path;
        });

        $_SERVER['HTTP_SEC_PURPOSE'] = 'prefetch';
        $this->request('/blog/how-to-build-a-cms');
        $firewall->run();

        $this->assertSame([], $recorded);
    }

    public function test_run_does_not_track_a_sub_resource_route(): void
    {
        $recorded = [];
        $firewall = XZeroProtect::init(['storage_path' => $this->tmpDir]);
        $firewall->enableTracking(function (VisitInfo $v) use (&$recorded) {
            $recorded[] = $v->path;
        });

        $_SERVER['HTTP_SEC_FETCH_DEST'] = 'image';
        $this->request('/captcha');
        $firewall->run();

        $this->assertSame([], $recorded);
    }

    public function test_run_honours_tracking_config(): void
    {
        $recorded = [];
        $firewall = XZeroProtect::init([
            'storage_path' => $this->tmpDir,
            'tracking'     => ['filter' => false],
        ]);
        $firewall->enableTracking(function (VisitInfo $v) use (&$recorded) {
            $recorded[] = $v->path;
        });

        $this->request('/assets/fonts/vazir.woff2');
        $firewall->run();

        $this->assertSame(['/assets/fonts/vazir.woff2'], $recorded);
    }
}
