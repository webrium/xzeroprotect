<?php

/**
 * Requests that must never be counted as a real page visit.
 *
 * Nothing here is ever blocked — these entries only affect visitor tracking.
 * A missing font or a favicon request is perfectly legitimate; it simply is
 * not a page view, and counting it inflates visit statistics.
 *
 * Matching:
 *   extensions : last path segment, case-insensitive
 *   paths      : case-insensitive prefix of the request path
 *
 * Extensions are limited to those that can never be an application route.
 * Ambiguous ones (.json, .html, .pdf, .xml, .txt) are handled as explicit
 * paths below instead, so apps that route them keep working.
 */
return [

    'extensions' => [
        // Stylesheets & scripts
        '.css', '.js', '.mjs', '.map',

        // Images
        '.jpg', '.jpeg', '.png', '.gif', '.webp', '.avif', '.svg', '.ico', '.bmp',

        // Fonts
        '.woff', '.woff2', '.ttf', '.otf', '.eot',

        // Media
        '.mp3', '.m4a', '.wav', '.ogg', '.mp4', '.webm',
    ],

    'paths' => [
        '/favicon.ico',
        '/apple-touch-icon',
        '/robots.txt',
        '/sitemap',
        '/ads.txt',
        '/browserconfig.xml',
        '/service-worker.js',
        '/sw.js',
        '/manifest.json',
        '/site.webmanifest',
        '/.well-known/',
    ],
];
