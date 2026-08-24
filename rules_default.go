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
	`/wp-config\.php\.(?:bak|old|save|orig|txt)`,
	`/xmlrpc\.php`,
	`/wp-content/(?:plugins|themes)/[^/]+/.*\.php`,
	`/wp-includes/.*\.php`,

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

	// Database and admin panels.
	`/(?:phpmyadmin|phpmyadm1n|pma|myadmin|mysqladmin)(?:/|$)`,
	`/adminer(?:\.php|/|$)`,
	`/(?:db|database|backup|dump|www|site|web)\.(?:sql|zip|tar\.gz|tgz|rar|7z)$`,

	// PHP webshells and known RCE entrypoints.
	`/(?:shell|c99|r57|wso|alfa|b374k|indoxploit|mini)\.php`,
	`/vendor/phpunit/phpunit/src/util/php/eval-stdin\.php`,
	`/_ignition/execute-solution`,
	`/index\.php\?s=/index/\\think`,
	`/(?:cgi-bin|scripts)/.*\.(?:sh|pl|cgi)$`,

	// Appliance and framework CVE probes seen constantly in the wild.
	`/boaform/(?:admin|formlogin)`,
	`/hnap1`,
	`/gponform/`,
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
	`\bl9(?:explore|tcpid)\b`,
	`\bcensysinspect\b`,
	`\binternet-measurement\.com\b`,
}

// defaultPayloadPatterns matches injection probes in query strings and bodies.
// The payload detector is off by default: it is the highest-false-positive and
// highest-CPU signal here, and it inspects attacker-controlled text on the
// request path.
var defaultPayloadPatterns = []string{
	// SQL injection.
	`union[\s/*]+select`,
	`select.{1,80}from\s+information_schema`,
	`\bor\b\s+1\s*=\s*1\b`,
	`'\s*or\s*'1'\s*=\s*'1`,
	`\bsleep\s*\(\s*\d+\s*\)`,
	`\bbenchmark\s*\(\s*\d+`,
	`\bwaitfor\s+delay\b`,

	// Path traversal and local file inclusion.
	`(?:\.\./){2,}`,
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
}
