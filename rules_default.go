package scanguard

// Default rulesets. These are regular expressions in RE2 syntax (Go's regexp
// package): no lookahead, no lookbehind, no backreferences. All matching is
// case-insensitive, so patterns are written in lower case.
//
// Curation principle: a default pattern must be something a legitimate client of
// a site that does not run the software in question would never request. Paths
// that are merely *sensitive* (/admin, /login, /api) are excluded — they are
// where false positives come from. Paths belonging to widely-deployed software
// whose own users would trip over them (Exchange autodiscover, ACME challenges)
// are excluded for the same reason.
//
// If you run WordPress, disable detectors.signatures or add an exclude for the
// wp-* patterns; otherwise your own admin traffic will ban you.

// defaultSignatures matches request paths that only a scanner asks for.
var defaultSignatures = []string{
	// WordPress — the single largest source of background scanning.
	`/wp-login\.php`,
	`/wp-admin(?:/|$)`,
	`/wp-config\.php`,
	`/xmlrpc\.php`,
	`/wp-content/(?:plugins|themes)/[^/]+/.*\.php`,
	// The whole directory, not just PHP inside it: the observed sweeps walk
	// /wp-includes/assets/, /wp-includes/js/jquery/, /wp-includes/l10n/ and friends
	// looking for a directory listing, and never reach a .php at all.
	`/wp-includes/`,

	// Joomla, the counterpart to the WordPress block above. Extension manifests are
	// the version-disclosure step of a Joomla sweep: every extension ships one, they
	// sit at a predictable path, and nothing renders them. A browser on a Joomla site
	// loads an extension's JS and CSS, never its XML.
	`/plugins/(?:editors|system|content|authentication|user)/[^/]+/.*\.xml$`,
	`/(?:components/com_|modules/mod_)[^/]+/.*\.xml$`,

	// Exposed VCS and editor metadata.
	`/\.git/(?:config|head|index|logs/head)`,
	`/\.svn/(?:entries|wc\.db)`,
	`/\.hg/requires`,
	`/\.bzr/`,
	`/\.idea/(?:workspace\.xml|modules\.xml)`,
	`/\.vscode/sftp\.json`,
	`/\.ds_store$`,

	// FTP/SFTP deployment credentials written by editor and IDE plugins. These are
	// probed as a SET, not individually: the scanner that asked for
	// /.vscode/sftp.json above requested /sftp-config.json in the same second, so
	// covering one file of the pair catches half a sweep and bans nobody. Each of
	// these stores host, username and password in plaintext, and no legitimate
	// client of any site has a reason to fetch one.
	`/sftp-config(?:-alt\d*)?\.json`,
	`/\.ftpconfig`,
	`/\.remote-sync\.json`,
	`/(?:sitemanager|recentservers)\.xml`,
	`/ws_ftp\.ini`,

	// Credentials and secrets left in webroots.
	`/\.env(?:$|[./])`,
	`/\.aws/credentials`,
	`/\.ssh/(?:id_[a-z0-9_]+|authorized_keys)`,
	`/\.npmrc$`,
	`/\.htpasswd$`,
	`/(?:credentials|secrets|id_rsa)(?:\.txt|\.json|\.yml|\.yaml)?$`,
	// Cloud, container and mail credentials, all dotfiles a webroot never serves.
	// Seen probed as one set by the same wordlists that ask for /.env: 1,616
	// requests from 108 addresses in nine days at one small deployment.
	`/\.(?:s3cfg|boto|netrc|msmtprc|esmtprc|gitconfig|amplifyrc|terraform\.tfstate)(?:$|[?/%])`,
	`/\.(?:docker/(?:config|secrets)\.json|terraform/credentials\.tfrc\.json)$`,
	// Framework configuration files that carry database and API credentials. None
	// is ever served by a correctly deployed application: Spring reads
	// application.properties off the classpath, ASP.NET reads appsettings.json off
	// disk, and neither maps into the webroot.
	`^/(?:config/)?(?:application|bootstrap)\.(?:properties|ya?ml)$`,
	`^/appsettings(?:\.[a-z]+)?\.json$`,
	// A backup of a WordPress config, which is the live credentials with an
	// extension that stops PHP executing it and starts the web server serving it.
	// Distinct from /wp-config.php itself, which a running site does have.
	`/\.?wp-config\.(?:php\.(?:bak|old|save|swp|orig|txt)|old|bak|save|orig|txt|dist|sample)$`,
	// rclone stores cloud-storage credentials here in plaintext.
	`/rclone\.conf$`,
	// Laravel's log, which routinely contains stack traces with connection strings.
	`/storage/logs/laravel\.log$`,

	// Database and admin panels.
	`/(?:phpmyadmin|phpmyadm1n|pma|myadmin|mysqladmin)(?:/|$)`,
	`/adminer(?:\.php|/|$)`,
	`/(?:db|database|backup|dump|www|site|web)\.(?:sql|zip|tar\.gz|tgz|rar|7z)$`,

	// PHP webshells and known RCE entrypoints.
	`/(?:shell|c99|r57|wso|alfa|b374k|indoxploit|mini)\.php`,
	`/vendor/phpunit/phpunit/src/util/php/eval-stdin\.php`,
	`/_ignition/(?:execute-solution|health-check)`,
	// Go's pprof handlers. net/http/pprof registers on DefaultServeMux, so this is
	// exposed by accident rather than on purpose, and it hands out heap dumps and
	// full goroutine stacks. 1,021 requests from 252 addresses in nine days.
	`^/debug/pprof(?:/|$)`,
	// A POST to an interpreter path is a command-execution attempt against an
	// appliance or a misconfigured CGI handler. No HTTP application routes these.
	`^/bin/(?:sh|bash|busybox)$`,
	`/(?:cgi-bin|scripts)/.*\.(?:sh|pl|cgi)$`,

	// Local-file-read targets and traversal, matched in the PATH.
	//
	// These same three patterns exist in defaultPayloadPatterns, and that is not a
	// duplication: the payload detector only ever inspects RawQuery, and the
	// signature detector only ever inspects req.URL.Path. Nothing inspects the full
	// URI, so a probe for /etc/passwd sent as a path -- which is how
	// /@fs/etc/passwd, /static../etc/passwd and /../../../../etc/passwd arrive --
	// is invisible to the query-side copy.
	//
	// Note Go does not clean dot segments out of a server-side request path, so
	// the traversal pattern sees them exactly as they were sent.
	//
	// Both separators, in both encodings. The plain `(?:\.\./){2,}` form missed
	// `..\..\..\var/log/apache2/access.log`, which is how the same wordlists send
	// it at a target they think is Windows. Go decodes %5C into a backslash in
	// URL.Path, so the decoded form is what a detector normally sees — but Traefik
	// can be configured to preserve encoded separators, and the payload copy of
	// this pattern reads RawQuery, which is never decoded. Hence all four.
	`/etc/(?:passwd|shadow)\b`,
	`/proc/self/(?:environ|cmdline)`,
	`(?:(?:\.\.|%2e%2e)(?:[\\/]|%2f|%5c)){2,}`,
	// Vite's dev server exposes arbitrary file reads under /@fs/ (CVE-2025-30208
	// and CVE-2025-30209). /@fs/ is an internal dev-server route: it has no meaning
	// in a production build, so nothing legitimate requests it.
	`/@fs/`,
	// The rest of the Vite dev-server namespace, same reasoning as /@fs/: a
	// production build never serves it, so a request is either a probe or a
	// deployment that shipped its dev server.
	`^/@vite/`,

	// A PHP file inside an upload or image directory. This is where a webshell lands
	// after an upload bypass, and it is the one place a correctly configured site
	// never executes PHP from — which is what keeps this off legitimate traffic.
	`/(?:uploads?|images?|img)/.*\.php$`,
	// blueimp jQuery-File-Upload. Only the handler class, never the upload endpoint
	// itself: a site using the library POSTs to /server/php/index.php as designed,
	// but UploadHandler.php is an include and is only ever fetched by a probe.
	`/server/php/uploadhandler\.php$`,

	// Appliance and framework CVE probes seen constantly in the wild.
	`/boaform/(?:admin|formlogin)`,
	`/hnap1`,
	`/gponform/`,
	`/goform/`,
	`/setup\.cgi`,
	`/remote/fgt_lang`,
	`/dana-na/`,
	`/\+cscoe\+/`,
	`/mifs/\.;/`,
	`/solr/[^/]+/(?:admin|config|dataimport)`,
	`/struts/[^/]*\.action`,
	`/manager/(?:html|text)/`,
	`/jenkins/script`,
	`/api/jsonws/invoke`,
	`/nacos/v1/(?:auth/users|cs/configs)`,
	`/druid/(?:index\.html|websession\.html)`,
	`/geoserver/web`,
	`/actuator/(?:env|heapdump|jolokia|threaddump)`,
	`/console/login/loginform\.jsp`,
	`/telescope/requests`,
	`/server-status$`,
	`/\.well-known/traffic-advice`,
}

// defaultUserAgents matches security tooling that identifies itself.
//
// Generic HTTP client strings (curl, python-requests, Go-http-client, wget) are
// deliberately absent: they are overwhelmingly used by legitimate automation,
// monitoring and API clients, and banning them is how you take down your own
// uptime checks. Add them yourself if your site genuinely has no API consumers.
var defaultUserAgents = []string{
	`\bnikto\b`,
	`\bsqlmap\b`,
	`\bnmap\s+scripting\s+engine\b`,
	`\bmasscan\b`,
	`\bzgrab\b`,
	`\bnuclei\b`,
	`\bacunetix\b`,
	`\bnetsparker\b`,
	`\bwpscan\b`,
	`\b(?:dirbuster|dirsearch|gobuster|feroxbuster|ffuf)\b`,
	`\bwhatweb\b`,
	`\bjoomscan\b`,
	`\b(?:arachni|w3af|skipfish)\b`,
	`\b(?:openvas|nessus)\b`,
	`\bmetasploit\b`,
	`\bhydra\b`,
	`\b(?:zmeu|morfeus)\b`,
	`\bxrumer\b`,
	`\bsemrushbot-ba\b`,
	`\bl9(?:explore|tcpid|scan)\b`,
	`\bcensysinspect\b`,
	`\binternet-measurement\.com\b`,

	// Internet-wide survey scanners that name themselves in the user-agent and
	// nowhere else. They are here rather than among the signatures because they
	// only ever request "/" — there is no path for a signature to match, so a
	// user-agent pattern is the only thing that can see them at all. Measured as
	// the single largest miss on a live deployment.
	//
	// Same category as censysinspect and internet-measurement.com above: honest,
	// non-destructive, and still a port scan of your estate. Remove them if you
	// would rather be surveyed.
	// Both halves of the observed string, so a change to either the greeting or
	// the documentation URL still matches.
	`hello from palo alto networks|\bcortex-xpanse\b`,
	// Single-CVE detection sweeps. The CVE and the tool name change every month,
	// so these match the shape rather than any one campaign: a user-agent that
	// names a CVE is announcing a vulnerability scan.
	`\bcve-\d{4}-\d{4,7}-(?:detect|scan|check|poc|exploit)\b`,
	`^cve-\d{4}-\d{4,7}(?:[/\s]|$)`,

	// A Chrome user-agent with no AppleWebKit and no Safari token. Real Chrome has
	// emitted both for its entire existence, so this string cannot come from the
	// browser it claims to be — it is forged, and badly. Worth its own entry
	// because the traffic behind it is invisible to every other detector: it
	// requests "/", "/login", "/signin" and "/api/auth/signin", which are real
	// endpoints, at roughly one attempt an hour per address. 4,277 requests from
	// 21 addresses in nine days at one deployment, every one a credential probe.
	`^mozilla/5\.0 \([^)]*\) chrome/[\d.]+$`,

	// Self-identifying scanners with no signature-visible path: like the survey
	// scanners above they mostly request "/", so the user-agent is the only thing
	// that can see them.
	`\blibredtail-http\b`,
	`\binfrawatch\b`,
	`\bmcpharvest\b`,
	`visionheight\.com/scan`,
}

// defaultCrawlers matches commercial SEO and backlink crawlers: bots that obey
// robots.txt and identify themselves honestly, but that many operators still do
// not want walking their site. They are NOT scanners, and detectors.userAgent
// therefore ignores them unless you opt in with detectors.userAgent.crawlers.
//
// SEARCH ENGINES ARE DELIBERATELY ABSENT. Googlebot, Bingbot, DuckDuckBot,
// Applebot, YandexBot and Baiduspider are how people find a site; banning one is
// a self-inflicted outage that takes weeks to notice and months to undo. If you
// genuinely want to block a search engine, do it in robots.txt, where it is
// visible and reversible — not from a middleware that answers 403.
//
// This list exists because of a real misdiagnosis worth recording: a query-string
// rule written for what looked like a CMS exploitation campaign turned out to be
// catching only MJ12bot, Barkrowler and DotBot re-crawling the URLs of a wiki
// that had been decommissioned days earlier. Crawler policy belongs in a setting
// that says "crawler", not in an injection rule.
var defaultCrawlers = []string{
	`\bmj12bot\b`,
	`\bbarkrowler\b`,
	`\bdotbot\b`,
	`\bahrefsbot\b`,
	`\bsemrushbot\b`,
	`\bblexbot\b`,
	`\bmegaindex\b`,
	`\bdataforseobot\b`,
	`\bserpstatbot\b`,
	`\bpetalbot\b`,
	`\bseekportbot\b`,
	`\bbytespider\b`,
}

// defaultPayloadPatterns matches injection probes in query strings and bodies.
// The payload detector is off by default: it is the highest-false-positive and
// highest-CPU signal here, and it inspects attacker-controlled text on the
// request path.
var defaultPayloadPatterns = []string{
	// ThinkPHP RCE. This lives here rather than in defaultSignatures because the
	// exploit is entirely in the query string, and req.URL.Path is split at the
	// first '?' -- a signature for it could never match.
	`s=/index/\\think`,
	// SQL injection.
	`union[\s/*]+select`,
	`select.{1,80}from\s+information_schema`,
	`\bor\b\s+1\s*=\s*1\b`,
	`'\s*or\s*'1'\s*=\s*'1`,
	`\bsleep\s*\(\s*\d+\s*\)`,
	`\bbenchmark\s*\(\s*\d+`,
	`\bwaitfor\s+delay\b`,

	// Path traversal and local file inclusion.
	`(?:(?:\.\.|%2e%2e)(?:[\\/]|%2f|%5c)){2,}`,
	`(?:%2e%2e(?:%2f|%5c)){2,}`,
	`/etc/(?:passwd|shadow)\b`,
	`/proc/self/environ`,
	`\bphp://(?:input|filter)`,
	`\bdata://text/plain`,

	// Template and expression injection.
	`\$\{jndi:(?:ldap|rmi|dns)`,
	`\$\{\s*[\w.]+\s*\}\s*$`,
	`\{\{\s*\d+\s*\*\s*\d+\s*\}\}`,

	// Command injection.
	`[;|&]\s*(?:cat|ls|id|whoami|uname|curl|wget|nc|bash|sh)\s`,
	`\$\(\s*(?:id|whoami|uname)\s*\)`,
	`\bcmd\.exe\b`,
	`\bpowershell(?:\.exe)?\s+-`,

	// Cross-site scripting.
	`<script[\s>]`,
	`\bon(?:error|load|mouseover)\s*=`,
	`javascript:\s*(?:alert|eval|fetch)`,
	`\bdocument\.cookie\b`,

	// PHP object injection / code execution.
	`\bbase64_decode\s*\(`,
	`\b(?:eval|assert|system|passthru|shell_exec)\s*\(`,
	`\bo:\d+:"[a-z_]`,

	// WordPress REST batch endpoint. Packing many sub-requests into one HTTP request
	// turns a per-request rate limit into a per-hundred one, which is what makes it
	// the current vehicle for WordPress credential stuffing.
	`\brest_route=/+batch/v\d`,
}
