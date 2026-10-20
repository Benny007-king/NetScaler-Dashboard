"""The hardening checklist shown on the Security tab.

Each entry is one thing to put in place on a NetScaler Gateway: what it does, the
commands, and how the dashboard recognises it on the appliance. Add an entry here
and it appears on the tab; `detect` names a function in security.py.

Command text is shown exactly as written. Placeholders in angle brackets are
filled in on the page: <GATEWAY_VSERVER> with a Gateway virtual server of the
selected instance, <DASHBOARD_ADDRESS> with this dashboard's address, <NSIP> with
the node's management address.
"""

# -------------------------------------------------------------- shared pieces
USER_LOG_PREREQ = r'''set audit syslogParams -userDefinedAuditlog YES
set audit nslogParams -userDefinedAuditlog YES'''

LOGIN_RESPONDERS = r'''add responder policy ICA_Gateway_Login_Audit_Responder_Policy "HTTP.REQ.METHOD.EQ(\"POST\") && HTTP.REQ.URL.PATH.CONTAINS(\"GetUserName\")\n" NOOP -logAction ICA_Gateway_Login_Audit_Message_Action

add responder policy Gateway_Login_Attempt_Audit_Responder_Policy "HTTP.REQ.METHOD.EQ(\"POST\") && HTTP.REQ.URL.PATH.CONTAINS(\"doAuthentication.do\")\n" NOOP -logAction Gateway_Login_Attempt_Audit_Message_Action'''

LOGIN_BIND = r'''bind vpn vserver <GATEWAY_VSERVER> -policy Gateway_Login_Attempt_Audit_Responder_Policy -priority 110 -gotoPriorityExpression NEXT -type AAA_REQUEST
bind vpn vserver <GATEWAY_VSERVER> -policy ICA_Gateway_Login_Audit_Responder_Policy -priority 120 -gotoPriorityExpression NEXT -type AAA_REQUEST'''

LOGIN_131 = r'''add audit messageaction ICA_Gateway_Login_Audit_Message_Action INFORMATIONAL "\"ICA Gateway Login SUCCESS | Client IP: \" + CLIENT.IP.SRC + \" | User: \" + AAA.USER.LOGIN_NAME + \" | Session ID: \" + AAA.USER.SESSIONID + \" | Gateway FQDN: \" + HTTP.REQ.HOSTNAME + \" | User-Agent: \" + HTTP.REQ.HEADER(\"User-Agent\") + \" | Timestamp: \" + SYS.TIME + \" | Note: Event may indicate a successful login or a browser refresh of an existing authenticated session. Verify using the Session ID.\""

add audit messageaction Gateway_Login_Attempt_Audit_Message_Action INFORMATIONAL "\"Gateway Login Attempt | Source IP: \" + CLIENT.IP.SRC + \" | Username: \" + AAA.LOGIN.USERNAME + \" | Gateway: \" + HTTP.REQ.HOSTNAME + \" | User-Agent: \" + HTTP.REQ.HEADER(\"User-Agent\") + \" | Time: \" + SYS.TIME + \" | Note: This log indicates a login attempt. Check subsequent logs to determine if authentication succeeded.\""'''

LOGIN_141 = r'''add audit messageaction ICA_Gateway_Login_Audit_Message_Action INFORMATIONAL "\"ICA Gateway Login SUCCESS | Client IP: \" + CLIENT.IP.SRC +\n\" | User: \" + AAA.USER.LOGIN_NAME +\n\" | Session ID: \" + AAA.USER.SESSIONID +\n\n\" | OS: \" +\nHTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Windows NT 10.0\").IF(\"Windows 10/11\",\nHTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Windows NT 6.3\").IF(\"Windows 8.1\",\nHTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Windows NT 6.2\").IF(\"Windows 8\",\nHTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Windows NT 6.1\").IF(\"Windows 7\",\nHTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Android\").IF(\"Android\",\nHTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"iPhone\").IF(\"iOS\",\nHTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Mac OS\").IF(\"macOS\",\"Unknown\"))))))) +\n\n\" | Access Type: \" +\n(\nHTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"CWAWEBVIEW\")\n.OR(HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"CitrixReceiver\"))\n.OR(HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"CitrixWorkspace\"))\n.OR(HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Citrix\"))\n).IF(\n HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"CWAWEBVIEW\").IF(\"Client - Citrix Workspace App (WebView)\",\n HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"CitrixReceiver\").IF(\"Client - Citrix Receiver\",\n HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"CitrixWorkspace\").IF(\"Client - Citrix Workspace App\",\"Client - Citrix Client\"))),\n HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Edg\").IF(\"Browser - Microsoft Edge\",\n HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Firefox\").IF(\"Browser - Firefox\",\n HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Chrome\").IF(\"Browser - Chrome\",\n HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Safari\").IF(\"Browser - Safari\",\"Not recognized\"))))\n) +\n\n\" | Gateway FQDN: \" + HTTP.REQ.HOSTNAME +\n\" | User-Agent: \" + HTTP.REQ.HEADER(\"User-Agent\") +\n\" | Timestamp: \" + SYS.TIME +\n\" | Note: Event may indicate a successful login or a browser refresh of an existing authenticated session. Verify using the Session ID.\""

add audit messageaction Gateway_Login_Attempt_Audit_Message_Action INFORMATIONAL "\"Gateway Login Attempt | Source IP: \" + CLIENT.IP.SRC +\n\" | Username: \" + AAA.LOGIN.USERNAME +\n\" | OS: \" +\nHTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Windows NT 10.0\").IF(\"Windows 10/11\",\nHTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Windows NT 6.3\").IF(\"Windows 8.1\",\nHTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Windows NT 6.2\").IF(\"Windows 8\",\nHTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Windows NT 6.1\").IF(\"Windows 7\",\nHTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Android\").IF(\"Android\",\nHTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"iPhone\").IF(\"iOS\",\nHTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Mac OS\").IF(\"macOS\",\"Unknown\"))))))) +\n\n\" | Access Type: \" +\n(\nHTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"CWAWEBVIEW\")\n.OR(HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"CitrixReceiver\"))\n.OR(HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"CitrixWorkspace\"))\n.OR(HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Citrix\"))\n).IF(\n HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"CWAWEBVIEW\").IF(\"Client - Citrix Workspace App (WebView)\",\n HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"CitrixReceiver\").IF(\"Client - Citrix Receiver\",\n HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"CitrixWorkspace\").IF(\"Client - Citrix Workspace App\",\"Client - Citrix Client\"))),\n HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Edg\").IF(\"Browser - Microsoft Edge\",\n HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Firefox\").IF(\"Browser - Firefox\",\n HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Chrome\").IF(\"Browser - Chrome\",\n HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Safari\").IF(\"Browser - Safari\",\"Not recognized\"))))\n) +\n\n\" | Gateway: \" + HTTP.REQ.HOSTNAME +\n\" | User-Agent: \" + HTTP.REQ.HEADER(\"User-Agent\") +\n\" | Time: \" + SYS.TIME +\n\" | Note: This log indicates a login attempt. Check subsequent logs to determine if authentication succeeded.\""'''


CHECKS = [
    # ===================================================== Gateway policies
    {
        "id": "login_audit",
        "group": "Gateway protection policies",
        "title": "Gateway login audit logging",
        "summary": "Writes one log line for every login attempt and every successful login on the Gateway.",
        "about": (
            "Two responder policies that do nothing to the traffic (NOOP) but write an audit message: one for "
            "every POST to doAuthentication.do (a login attempt, with the user name typed) and one for every "
            "POST to GetUserName (a successful login or a refresh of an authenticated session, with the AAA "
            "session id). The 14.1 version also works out the client's operating system and whether it came "
            "from Citrix Workspace app or a browser. The dashboard reads these lines and shows them on the "
            "Sessions tab (operating system, access type, Gateway name, user agent, real login time) and in "
            "the activity below."),
        "notes": [
            "User-defined audit messages are only logged after `set audit syslogParams -userDefinedAuditlog YES` "
            "(and the same for nslogParams) - without it the policies match but nothing is written.",
            "The original 13.1 commands had the message actions only; the two responder policies (the same for "
            "both versions) are what actually writes them, so they are included in both.",
            "Bind them with gotoPriorityExpression NEXT: they only log, so evaluation has to continue to the "
            "blocking policies after them.",
        ],
        "variants": [
            {"label": "NetScaler 14.1", "match": r"^14\.", "commands": [
                ("Prerequisite: log user-defined messages", USER_LOG_PREREQ),
                ("Message actions", LOGIN_141),
                ("Responder policies", LOGIN_RESPONDERS),
                ("Bind to the Gateway (AAA request)", LOGIN_BIND)]},
            {"label": "NetScaler 13.1", "match": r"^13\.", "commands": [
                ("Prerequisite: log user-defined messages", USER_LOG_PREREQ),
                ("Message actions", LOGIN_131),
                ("Responder policies", LOGIN_RESPONDERS),
                ("Bind to the Gateway (AAA request)", LOGIN_BIND)]},
        ],
        "policies": ["Gateway_Login_Attempt_Audit_Responder_Policy", "ICA_Gateway_Login_Audit_Responder_Policy"],
        "signatures": [["doauthentication.do", "noop"], ["getusername", "noop"]],
        "detect": "login_audit",
    },
    {
        "id": "brute_force",
        "group": "Gateway protection policies",
        "title": "Brute-force login protection (rate limiter)",
        "summary": "Drops logins from an address that tried more than 10 times in 10 minutes.",
        "about": (
            "A stream selector keys requests on URL + client address, a limit identifier allows 10 of them in "
            "a 10-minute window, and a responder policy drops further POSTs to /nf/auth/doAuthentication.do "
            "from that address while it is over the limit, logging 'Possible brute force login attack'."),
        "notes": [
            "It counts every login request from the address, successful ones too - not only failures. A user "
            "who signs in many times through one shared NAT address can reach the limit.",
            "Corrected from the original: the selector was created as Check_Failed_Logins_Selector_Policy but "
            "the limit identifier refers to Check_Failed_Logins_Selector, so the limit identifier could not be "
            "created; the client-address expression had stray tab characters around it.",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("Selector and limit", r'''add stream selector Check_Failed_Logins_Selector HTTP.REQ.URL CLIENT.IP.SRC

add ns limitIdentifier Check_Failed_Logins_Limit_Identifier -threshold 10 -timeSlice 600000 -selectorName Check_Failed_Logins_Selector -trapsInTimeSlice 10'''),
            ("Log message and responder policy", r'''add audit messageaction Possible_Brute_Force_Login_Attack_Message_Action INFORMATIONAL "\"Max login attempts detected from \" + CLIENT.IP.SRC + \" to \"+ HTTP.REQ.HOSTNAME +\" \" + HTTP.REQ.URL + \" Possible brute force login attack, The client IP address will be blocked for 10 minutes.\""

add responder policy Error_Login_Block_Responder_Policy "(HTTP.REQ.URL.EQ(\"/nf/auth/doAuthentication.do\")) && SYS.CHECK_LIMIT(\"Check_Failed_Logins_Limit_Identifier\")" DROP -logAction Possible_Brute_Force_Login_Attack_Message_Action'''),
            ("Bind to the Gateway (AAA request)", r'''bind vpn vserver <GATEWAY_VSERVER> -policy Error_Login_Block_Responder_Policy -priority 130 -gotoPriorityExpression END -type AAA_REQUEST'''),
        ]}],
        "policies": ["Error_Login_Block_Responder_Policy"],
        "signatures": [["sys.check_limit(", "doauthentication.do"]],
        "detect": "brute_force",
    },
    {
        "id": "cookie_hijack",
        "group": "Gateway protection policies",
        "title": "Session cookie hijack prevention",
        "summary": "Resets a connection that presents a valid session cookie from a different client address.",
        "about": (
            "An authenticated Gateway session remembers the address it was created from. When a request "
            "carries that session's cookie but comes from another address, the connection is reset and "
            "'Possible session cookie hijack attack' is logged - a stolen NSC_AAAC cookie cannot be replayed "
            "from somewhere else."),
        "notes": [
            "Users whose public address changes during a session (mobile networks, some proxies or load-balanced "
            "egress) are reset and have to sign in again.",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("Log message and responder policy", r'''add audit messageaction Possible_Session_Cookie_Hijack_Attack_Message_Action INFORMATIONAL "\"Session cookie invalid detected from \" + CLIENT.IP.SRC + \" to \"+ HTTP.REQ.HOSTNAME +\" \" + HTTP.REQ.URL + \" Possible session cookie hijack attack, the client get session reset.\""

add responder policy Session_Cookie_Hijack_Block_Responder_Policy "AAA.USER.NAME.LENGTH.NE(0) && AAA.USER.SOURCEIP.NE(CLIENT.IP.SRC)" RESET -logAction Possible_Session_Cookie_Hijack_Attack_Message_Action'''),
            ("Bind to the Gateway (AAA request)", r'''bind vpn vserver <GATEWAY_VSERVER> -policy Session_Cookie_Hijack_Block_Responder_Policy -priority 140 -gotoPriorityExpression END -type AAA_REQUEST'''),
        ]}],
        "policies": ["Session_Cookie_Hijack_Block_Responder_Policy"],
        "signatures": [["aaa.user.sourceip.ne(client.ip.src)"]],
        "detect": "responder",
    },
    {
        "id": "malicious_ip",
        "group": "Gateway protection policies",
        "title": "Drop known malicious addresses (IP reputation)",
        "summary": "Drops requests from addresses NetScaler's IP reputation service lists as malicious.",
        "about": (
            "CLIENT.IP.SRC.IPREP_IS_MALICIOUS asks the IP reputation database (Webroot) whether the client "
            "address is a known source of attacks - botnets, scanners, spam and phishing hosts - and the "
            "request is dropped before it reaches the login page."),
        "notes": [
            "Needs the Reputation feature enabled and licensed, and the appliance must reach the reputation "
            "service on the internet to download updates.",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("Enable the feature", r'''enable ns feature reputation'''),
            ("Responder policy", r'''add responder policy Drop_Malicious_IP CLIENT.IP.SRC.IPREP_IS_MALICIOUS DROP'''),
            ("Bind to the Gateway (AAA request)", r'''bind vpn vserver <GATEWAY_VSERVER> -policy Drop_Malicious_IP -priority 100 -gotoPriorityExpression END -type AAA_REQUEST'''),
        ]}],
        "policies": ["Drop_Malicious_IP"],
        "signatures": [["iprep_is_malicious"]],
        "detect": "malicious_ip",
    },
    {
        "id": "epa_referer",
        "group": "Gateway protection policies",
        "title": "EPA script requests must come from the Gateway page",
        "summary": "Drops requests for /epa/scripts/ that have no Referer header.",
        "about": (
            "The Endpoint Analysis (EPA) scripts are only ever loaded by the Gateway's own pages, which send a "
            "Referer. A request for them without one is somebody probing the scripts directly."),
        "notes": ["Only relevant when the Gateway uses Endpoint Analysis - otherwise mark it 'Not relevant'."],
        "variants": [{"label": "All versions", "commands": [
            ("Responder policy", r'''add responder policy Block_EPA_Referer_Policy "HTTP.REQ.URL.PATH.TO_LOWER.CONTAINS(\"/epa/scripts/\") && HTTP.REQ.HEADER(\"Referer\").EXISTS.NOT" DROP'''),
            ("Bind to the Gateway (AAA request)", r'''bind vpn vserver <GATEWAY_VSERVER> -policy Block_EPA_Referer_Policy -priority 150 -gotoPriorityExpression END -type AAA_REQUEST'''),
        ]}],
        "policies": ["Block_EPA_Referer_Policy"],
        "signatures": [["/epa/scripts/", "referer"]],
        "detect": "responder",
        "optional": True,
    },
    {
        "id": "saml_protection",
        "group": "Gateway protection policies",
        "title": "SAML hardening",
        "summary": "Drops oversized or malformed SAML requests and responses before they are parsed.",
        "about": (
            "Matches POSTs to /cgi/samlauth (the Gateway as a SAML service provider) and /saml/login (as an "
            "identity provider) and drops them when the body is over 128 KB, carries the SAML field more than "
            "once, or the decoded XML has an abnormally long InclusiveNamespaces PrefixList - the shapes used "
            "to attack the SAML parser. Bound globally with REQ_OVERRIDE so it runs before anything else."),
        "notes": ["Only relevant when the appliance does SAML (as service provider or identity provider)."],
        "variants": [{"label": "All versions", "commands": [
            ("Responder policy", r'''add responder policy SAML_prefix_Block_Policy "(HTTP.REQ.URL.PATH.SET_TEXT_MODE(IGNORECASE).STARTSWITH(\"/cgi/samlauth\") && (HTTP.REQ.CONTENT_LENGTH.GT(131072) || HTTP.REQ.BODY(131072).SET_TEXT_MODE(URLENCODED).DECODE_USING_TEXT_MODE.TYPECAST_NVLIST_T('=','&').SET_TEXT_MODE(IGNORECASE).NAME_COUNT(\"SAMLResponse\").GT(1) || HTTP.REQ.BODY(131072).SET_TEXT_MODE(URLENCODED).DECODE_USING_TEXT_MODE.TYPECAST_NVLIST_T('=','&').SET_TEXT_MODE(IGNORECASE).VALUE(\"SAMLResponse\").B64DECODE.SET_TEXT_MODE(IGNORECASE).REGEX_MATCH(re#PrefixList\s*=\s*[\"'](([^\"'\s]*\s){15}|[^\"']{256,})#))) || (HTTP.REQ.URL.PATH.SET_TEXT_MODE(IGNORECASE).STARTSWITH(\"/saml/login\") && (HTTP.REQ.CONTENT_LENGTH.GT(131072) || HTTP.REQ.BODY(131072).SET_TEXT_MODE(URLENCODED).DECODE_USING_TEXT_MODE.TYPECAST_NVLIST_T('=','&').SET_TEXT_MODE(IGNORECASE).NAME_COUNT(\"SAMLRequest\").GT(1) || HTTP.REQ.BODY(131072).SET_TEXT_MODE(URLENCODED).DECODE_USING_TEXT_MODE.TYPECAST_NVLIST_T('=','&').SET_TEXT_MODE(IGNORECASE).VALUE(\"SAMLRequest\").B64DECODE.SET_TEXT_MODE(IGNORECASE).REGEX_MATCH(re#PrefixList\s*=\s*[\"'](([^\"'\s]*\s){15}|[^\"']{256,})#)))" DROP DROP'''),
            ("Bind globally (before everything else)", r'''bind responder global SAML_prefix_Block_Policy 100 END -type REQ_OVERRIDE'''),
        ]}],
        "policies": ["SAML_prefix_Block_Policy"],
        "signatures": [["/cgi/samlauth", "prefixlist"], ["/saml/login", "prefixlist"]],
        "detect": "responder",
        "optional": True,
    },

    # ===================================================== appliance settings
    {
        "id": "waf",
        "group": "Gateway settings",
        "title": "Built-in WAF protection for Auth, VPN and Portal",
        "summary": "NetScaler's built-in Web App Firewall protection covers the Gateway's authentication, VPN and portal endpoints.",
        "about": (
            "`set aaa parameter -wafProtection` switches on the Web App Firewall protection NetScaler builds in for "
            "its own Gateway endpoints, without a WAF profile of your own: AUTH for the authentication pages, VPN "
            "for the VPN endpoints and PORTAL for the portal pages. The dashboard checks that all three are listed."),
        "notes": [
            "DEFAULT leaves the choice to the build, and DISABLED turns the protection off.",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("Setting", r"set aaa parameter -wafProtection AUTH VPN PORTAL")]}],
        "detect": "waf",
    },
    {
        "id": "csp_header",
        "group": "Gateway settings",
        "title": "Content-Security-Policy header on the Gateway",
        "summary": "Tells browsers which sources the Gateway pages may load scripts and frames from.",
        "about": (
            "A rewrite policy adds a Content-Security-Policy header to the Gateway's responses (unless the "
            "page already sets one). Injected script from another host is then refused by the browser, and "
            "frame-ancestors stops other sites from framing the login page (clickjacking)."),
        "notes": [
            "The Gateway's own pages need 'unsafe-inline' and 'unsafe-eval'; test a stricter policy before "
            "using it.",
            "Needs the Rewrite feature: `enable ns feature rewrite`.",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("Rewrite action and policy", r'''enable ns feature rewrite
add rewrite action Gateway_CSP_Header_Action insert_http_header Content-Security-Policy "\"default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; frame-ancestors 'self'\""
add rewrite policy Gateway_CSP_Header_Policy "HTTP.RES.HEADER(\"Content-Security-Policy\").EXISTS.NOT" Gateway_CSP_Header_Action'''),
            ("Bind to the Gateway (responses)", r'''bind vpn vserver <GATEWAY_VSERVER> -policy Gateway_CSP_Header_Policy -priority 100 -gotoPriorityExpression NEXT -type RESPONSE'''),
        ]}],
        "detect": "csp",
    },
    {
        "id": "httponly",
        "group": "Gateway settings",
        "title": "HttpOnly flag on authentication cookies",
        "summary": "Scripts in the browser cannot read the Gateway's session cookies (NSC_AAAC, NSC_TMAS).",
        "about": (
            "With the HttpOnly flag the authentication cookies are sent to the Gateway but are invisible to "
            "JavaScript, so a cross-site scripting flaw cannot steal the session."),
        "notes": [
            "Available from NetScaler 13.1-37; on by default from 13.1-59.19 and 14.1-43.56.",
            "Applies to nFactor (advanced) authentication; classic authentication does not set it.",
            "On older Citrix Secure Access clients the Home Page button stops working (fixed in Secure Access "
            "for Windows 24.8.1 with Gateway 14.1-34).",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("Setting", r'''set aaa parameter -httpOnlyCookie ENABLED''')]}],
        "detect": "httponly",
    },
    {
        "id": "cookie_v1",
        "group": "Gateway settings",
        "title": "Cookie version 1",
        "summary": "Cookies NetScaler sets use version 1 (Max-Age) instead of version 0 (Expires).",
        "about": (
            "Version 1 cookies carry a relative Max-Age instead of an absolute Expires date, so their lifetime "
            "does not depend on the client's clock, and they follow the stricter cookie specification."),
        "notes": [],
        "variants": [{"label": "All versions", "commands": [
            ("Setting", r'''set ns param -cookieversion 1''')]}],
        "detect": "cookie_v1",
    },
    {
        "id": "tcp_isn",
        "group": "Management and platform",
        "title": "Enhanced TCP ISN generation",
        "summary": "The initial sequence numbers in the appliance's SYN-ACKs vary more, so they cannot be guessed.",
        "about": (
            "Every TCP connection starts from an initial sequence number (ISN) chosen by each side. With enhanced "
            "ISN generation the NetScaler varies the ISN in the SYN-ACKs it sends more widely, which makes it far "
            "harder for an attacker to predict it and inject spoofed packets into, or reset, a connection they "
            "cannot see."),
        "notes": ["Off by default."],
        "variants": [{"label": "All versions", "commands": [
            ("Setting", r"set ns tcpparam -enhancedISNgeneration ENABLED")]}],
        "detect": "tcp_isn",
    },
    {
        "id": "mgmt_secure",
        "group": "Management and platform",
        "title": "Secure-only management access",
        "summary": "The management GUI and NITRO API answer on HTTPS only, never on plain HTTP.",
        "about": (
            "With -gui SECUREONLY the management address refuses HTTP: the nsroot password and NITRO "
            "credentials can no longer cross the network in clear text. The same applies to every SNIP that "
            "has management access enabled."),
        "notes": [
            "This dashboard talks NITRO to the node too: after the change set the node to HTTPS / 443 in "
            "Settings, or it stops reaching it.",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("Management address", r'''set ns ip <NSIP> -gui SECUREONLY''')]}],
        "detect": "mgmt_secure",
    },
    {
        "id": "syslog_dashboard",
        "group": "Management and platform",
        "title": "Send logs to this dashboard",
        "summary": "The NetScaler sends its audit log here, so every WAF violation and policy hit is kept.",
        "about": (
            "Without it the dashboard can only read the last 256 lines of the appliance's audit log once a "
            "minute, and violations that scroll past in between are lost. With a syslog server pointing here "
            "every WAF violation, brute-force block, hijack reset and login line is received and stored for "
            "the retention period (in the external database too, when one is connected)."),
        "notes": [
            "The dashboard listens on UDP and TCP 514 and only accepts messages from the management address "
            "of a node configured in Settings.",
            "Log level INFORMATIONAL is needed: the login and policy messages are written at that level.",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("Syslog server, policy and global binding", r'''add audit syslogAction Dashboard_Syslog_Action <DASHBOARD_ADDRESS> -serverPort 514 -logLevel EMERGENCY ALERT CRITICAL ERROR WARNING NOTICE INFORMATIONAL -userDefinedAuditlog YES -transport UDP
add audit syslogPolicy Dashboard_Syslog_Policy true Dashboard_Syslog_Action
bind audit syslogGlobal -policyName Dashboard_Syslog_Policy -priority 100'''),
            ("Full WAF violation detail (CEF format)", r'''set appfw settings -CEFLogging ON'''),
        ]}],
        "detect": "syslog",
    },
]


# ------------------------------------------------------------ added in 1.19.0
CHECKS += [
    {
        "id": "tls_versions",
        "group": "Gateway settings",
        "title": "Only TLS 1.2 and 1.3 on the Gateway",
        "summary": "SSLv3, TLS 1.0 and TLS 1.1 are switched off on every Gateway virtual server.",
        "about": (
            "SSLv3, TLS 1.0 and TLS 1.1 have known weaknesses (POODLE, BEAST, weak hashes) and no current client "
            "needs them. With only TLS 1.2 and 1.3 enabled, a client cannot be talked down to a protocol an attacker "
            "can break."),
        "notes": [
            "When an SSL profile is bound to the virtual server (or the default profiles are enabled with "
            "`set ssl parameter -defaultProfile ENABLED`), the protocols are set on the profile, not on the virtual "
            "server - the dashboard reads whichever applies.",
            "Very old Citrix Receiver versions (before 4.x) cannot connect without TLS 1.0.",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("On the Gateway virtual server", r"set ssl vserver <GATEWAY_VSERVER> -ssl3 DISABLED -tls1 DISABLED -tls11 DISABLED -tls12 ENABLED -tls13 ENABLED"),
            ("...or on its SSL profile, when one is bound", r"set ssl profile <SSL_PROFILE> -ssl3 DISABLED -tls1 DISABLED -tls11 DISABLED -tls12 ENABLED -tls13 ENABLED"),
        ]}],
        "detect": "tls_versions",
    },
    {
        "id": "hsts",
        "group": "Gateway settings",
        "title": "HSTS on the Gateway",
        "summary": "Browsers are told to use only HTTPS for the Gateway, for a year.",
        "about": (
            "HTTP Strict Transport Security makes the browser refuse plain HTTP to the Gateway's host name once it "
            "has seen the header, so a man in the middle cannot strip HTTPS from the first request (SSL stripping)."),
        "notes": ["Available from NetScaler 12.0; on a bound SSL profile the setting lives on the profile."],
        "variants": [{"label": "All versions", "commands": [
            ("On the Gateway virtual server", r"set ssl vserver <GATEWAY_VSERVER> -HSTS ENABLED -maxage 31536000 -IncludeSubdomains YES"),
            ("...or on its SSL profile, when one is bound", r"set ssl profile <SSL_PROFILE> -HSTS ENABLED -maxage 31536000 -IncludeSubdomains YES"),
        ]}],
        "detect": "hsts",
    },
    {
        "id": "ssl_reneg",
        "group": "Gateway settings",
        "title": "No insecure TLS renegotiation",
        "summary": "Only secure (RFC 5746) renegotiation is accepted.",
        "about": (
            "Renegotiation without the RFC 5746 extension lets an attacker splice their own request in front of a "
            "user's (CVE-2009-3555) and can be used to exhaust the appliance's CPU. NONSECURE refuses it and keeps "
            "secure renegotiation working; ALL refuses renegotiation entirely."),
        "notes": [],
        "variants": [{"label": "All versions", "commands": [
            ("Setting", r"set ssl parameter -denySSLReneg NONSECURE")]}],
        "detect": "ssl_reneg",
    },
    {
        "id": "http_invalid",
        "group": "Gateway settings",
        "title": "Drop invalid HTTP requests",
        "summary": "Requests that do not follow the HTTP standard are dropped by the default HTTP profile.",
        "about": (
            "Requests that break the HTTP standard are a common way to smuggle requests past inspection (request "
            "smuggling) or to probe for parser flaws. With dropInvalReqs the appliance drops them instead of passing "
            "them on."),
        "notes": ["An HTTP profile bound to a virtual server overrides the default profile for it."],
        "variants": [{"label": "All versions", "commands": [
            ("Default HTTP profile", "set ns httpProfile nshttp_default_profile -dropInvalReqs ENABLED")]}],
        "detect": "http_invalid",
    },
    {
        "id": "http09",
        "group": "Gateway settings",
        "title": "Mark HTTP/0.9 requests as invalid",
        "summary": "HTTP/0.9 requests (no version, no headers) count as invalid.",
        "about": (
            "HTTP/0.9 has no headers and no version, so nothing in the request can be checked - no browser has sent "
            "one for decades, but scanners and smuggling attempts do. Marked invalid, they are dropped together with "
            "the other invalid requests."),
        "notes": ["Takes effect with 'Drop invalid HTTP requests' - marking alone does not drop them."],
        "variants": [{"label": "All versions", "commands": [
            ("Default HTTP profile", "set ns httpProfile nshttp_default_profile -markHttp09Inval ENABLED")]}],
        "detect": "http09",
    },
    {
        "id": "http_connect",
        "group": "Gateway settings",
        "title": "Mark CONNECT requests as invalid",
        "summary": "HTTP CONNECT (proxy tunnel) requests count as invalid.",
        "about": (
            "CONNECT asks a proxy to open a tunnel to another host. A Gateway is not a forward proxy, so a CONNECT "
            "request is somebody trying to use it as one - to reach internal hosts or to hide where traffic goes."),
        "notes": ["Takes effect with 'Drop invalid HTTP requests'."],
        "variants": [{"label": "All versions", "commands": [
            ("Default HTTP profile", "set ns httpProfile nshttp_default_profile -markConnReqInval ENABLED")]}],
        "detect": "http_connect",
    },
    {
        "id": "auth_feedback",
        "group": "Gateway settings",
        "title": "Login errors do not reveal account details",
        "summary": "A failed Gateway login does not say whether the user exists or the account is locked.",
        "about": (
            "With enhanced authentication feedback the login page tells the user why a login failed - the user "
            "does not exist, the password expired, the account is locked. That is also a free way for an attacker "
            "to find out which user names are real. Switched off, every failure gets the same message."),
        "notes": [],
        "variants": [{"label": "All versions", "commands": [
            ("Setting", r"set aaa parameter -enableEnhancedAuthFeedback NO")]}],
        "detect": "auth_feedback",
    },
    {
        "id": "mgmt_restrict",
        "group": "Management and platform",
        "title": "Management address serves management only",
        "summary": "The NSIP refuses traffic for anything that is not a management application.",
        "about": (
            "With restrictAccess the management address answers only management protocols (GUI, NITRO, SSH), so "
            "nothing else - a mistakenly bound virtual server, another service - can be reached through it. "
            "The same applies to a SNIP that has management access enabled."),
        "notes": [],
        "variants": [{"label": "All versions", "commands": [
            ("Management address", r"set ns ip <NSIP> -restrictAccess ENABLED")]}],
        "detect": "mgmt_restrict",
    },
    {
        "id": "mgmt_services",
        "group": "Management and platform",
        "title": "Telnet and FTP off on management addresses",
        "summary": "No clear-text management protocols are reachable.",
        "about": (
            "Telnet and FTP send the administrator's password unencrypted. SSH and SFTP do the same job encrypted, "
            "so the clear-text ones should be off on the NSIP and on any SNIP with management access."),
        "notes": [],
        "variants": [{"label": "All versions", "commands": [
            ("Management address", r"set ns ip <NSIP> -telnet DISABLED -ftp DISABLED")]}],
        "detect": "mgmt_services",
    },
    {
        "id": "sys_passwords",
        "group": "Management and platform",
        "title": "Strong passwords for management accounts",
        "summary": "Local system users need complex passwords of at least 8 characters, and nsroot must change the default.",
        "about": (
            "strongpassword makes local system user passwords contain upper and lower case letters, digits and "
            "special characters; minpasswordlen sets their minimum length; forcePasswordChange makes nsroot "
            "choose a new password at the first login instead of keeping the default."),
        "notes": ["Existing passwords are not checked again - the rules apply when a password is set."],
        "variants": [{"label": "All versions", "commands": [
            ("Setting", r"set system parameter -strongpassword enableall -minpasswordlen 8 -forcePasswordChange ENABLED")]}],
        "detect": "sys_passwords",
    },
    {
        "id": "ntp",
        "group": "Management and platform",
        "title": "Time synchronised (NTP)",
        "summary": "The appliance keeps its clock in step with a time server.",
        "about": (
            "Log times only mean something when the clock is right: correlating a WAF violation with a login, a "
            "SIEM, or an incident timeline needs it. Kerberos, SAML and OTP authentication also fail when the clock "
            "drifts by minutes."),
        "notes": [],
        "variants": [{"label": "All versions", "commands": [
            ("Time server and synchronisation", "add ntp server <NTP_SERVER>\nenable ntp sync")]}],
        "detect": "ntp",
    },
    {
        "id": "firmware",
        "group": "Management and platform",
        "title": "Firmware includes the 2025 Gateway security fixes",
        "summary": "The build is not older than the fixes for CVE-2025-5777 (CitrixBleed 2), CVE-2025-6543 and CVE-2025-7775.",
        "about": (
            "CVE-2025-5777 leaks memory - session tokens included - from Gateway and AAA virtual servers; "
            "CVE-2025-6543 and CVE-2025-7775 allow code execution on them. All three were exploited in the wild. "
            "They are fixed in 14.1-47.48 and 13.1-59.22 (and later builds of each)."),
        "notes": [
            "This is what was known when this dashboard version was made. Check NetScaler's security bulletins "
            "for anything newer.",
            "After upgrading from a vulnerable build, end all ICA and PCoIP sessions: `kill icaconnection -all` "
            "and `kill pcoipConnection -all` - stolen session tokens survive the upgrade otherwise.",
            "13.1-FIPS / NDcPP builds have their own fixed build numbers (13.1-37.241 or later).",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("After the upgrade", "kill icaconnection -all\nkill pcoipConnection -all")]}],
        "detect": "firmware",
    },
]

# Shown in this order on the tab.
GROUP_ORDER = ["Gateway protection policies", "Gateway settings", "Management and platform"]
CHECKS.sort(key=lambda c: GROUP_ORDER.index(c["group"]))


# ------------------------------------------------------------ added in 1.20.0
CHECKS += [
    {
        "id": "ciphers",
        "group": "Gateway settings",
        "title": "Strong ciphers only on the Gateway",
        "summary": "No RC4, DES/3DES, export, NULL or MD5 ciphers on the Gateway virtual servers.",
        "about": (
            "The cipher list decides how the TLS connection is encrypted. RC4, DES and 3DES, export-grade, NULL and "
            "MD5 ciphers are broken or too weak; CBC ciphers with SHA-1 are dated. A group with only TLS 1.3 and "
            "ECDHE with AES-GCM or ChaCha20 gives forward secrecy and authenticated encryption to every current "
            "client."),
        "notes": [
            "The dashboard reads the ciphers bound to the Gateway virtual server, or to its SSL profile, and opens "
            "cipher groups to see what is in them. The built-in DEFAULT group counts as Partly.",
            "The ECDSA ciphers are only used with an ECDSA certificate, the RSA ones with an RSA certificate.",
            "On 13.1, TLS 1.3 ciphers need the enhanced SSL profiles (`set ssl parameter -defaultProfile ENABLED`).",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("A strong cipher group", "add ssl cipher Gateway_Strong_Ciphers\n"
             "bind ssl cipher Gateway_Strong_Ciphers -cipherName TLS1.3-AES256-GCM-SHA384\n"
             "bind ssl cipher Gateway_Strong_Ciphers -cipherName TLS1.3-CHACHA20-POLY1305-SHA256\n"
             "bind ssl cipher Gateway_Strong_Ciphers -cipherName TLS1.3-AES128-GCM-SHA256\n"
             "bind ssl cipher Gateway_Strong_Ciphers -cipherName TLS1.2-ECDHE-ECDSA-AES256-GCM-SHA384\n"
             "bind ssl cipher Gateway_Strong_Ciphers -cipherName TLS1.2-ECDHE-ECDSA-AES128-GCM-SHA256\n"
             "bind ssl cipher Gateway_Strong_Ciphers -cipherName TLS1.2-ECDHE-RSA-AES256-GCM-SHA384\n"
             "bind ssl cipher Gateway_Strong_Ciphers -cipherName TLS1.2-ECDHE-RSA-AES128-GCM-SHA256"),
            ("On the Gateway virtual server", "unbind ssl vserver <GATEWAY_VSERVER> -cipherName DEFAULT\n"
             "bind ssl vserver <GATEWAY_VSERVER> -cipherName Gateway_Strong_Ciphers"),
            ("...or on its SSL profile, when one is bound", "bind ssl profile <SSL_PROFILE> -cipherName Gateway_Strong_Ciphers -cipherPriority 1"),
        ]}],
        "detect": "ciphers",
    },
    {
        "id": "gw_timeouts",
        "group": "Gateway settings",
        "title": "Gateway sessions time out",
        "summary": "An idle session ends within an hour, and every session ends after a maximum time.",
        "about": (
            "A Gateway session left open on a shared or stolen device is a way in. The idle timeout ends it when "
            "nothing happens; the forced timeout ends it after a fixed time however busy it is, so a session (or a "
            "stolen session cookie) cannot live for days."),
        "notes": [
            "Session policies can set their own timeouts (`set vpn sessionAction ... -sessTimeout`), which win over "
            "these global ones for the users they apply to.",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("Setting (minutes)", "set vpn parameter -sessTimeout 30 -forcedTimeout 720")]}],
        "detect": "gw_timeouts",
    },
    {
        "id": "login_lockout",
        "group": "Gateway settings",
        "title": "Accounts lock after repeated failed logins",
        "summary": "After 5 wrong passwords a user is locked out of the Gateway for a while.",
        "about": (
            "Without a limit an attacker can try passwords for a user for ever (password spraying, brute force). "
            "maxLoginAttempts locks the account on the Gateway after that many failures, for failedLoginTimeout "
            "minutes - before the directory's own lockout locks the user out of everything."),
        "notes": [
            "Locked users can be freed early on the Unlock User tab.",
            "Keep the number below the directory's own lockout threshold, so the Gateway locks first.",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("Setting", "set aaa parameter -maxLoginAttempts 5 -failedLoginTimeout 15")]}],
        "detect": "login_lockout",
    },
    {
        "id": "clientless_off",
        "group": "Gateway settings",
        "title": "Clientless access off when it is not used",
        "summary": "Clientless VPN (web applications through the Gateway's own rewriting) is switched off.",
        "about": (
            "Clientless access rewrites web applications so they can be used through the Gateway without a client. "
            "Its URL rewriting and proxy endpoints are a large attack surface that most ICA-proxy and full-VPN "
            "deployments never use."),
        "notes": ["Only when clientless access is not used - otherwise mark it 'Not relevant'."],
        "variants": [{"label": "All versions", "commands": [
            ("Setting", "set vpn parameter -clientlessVpnMode OFF")]}],
        "detect": "clientless_off",
        "optional": True,
    },
    {
        "id": "mgmt_timeout",
        "group": "Management and platform",
        "title": "Management sessions time out",
        "summary": "An idle GUI, CLI or NITRO session of an administrator ends after at most 15 minutes.",
        "about": (
            "An administrator's session left open on a workstation gives full control of the appliance. The system "
            "timeout ends idle management sessions."),
        "notes": [],
        "variants": [{"label": "All versions", "commands": [
            ("Setting (seconds)", "set system parameter -timeout 600")]}],
        "detect": "mgmt_timeout",
    },
    {
        "id": "snmp_v3",
        "group": "Management and platform",
        "title": "SNMP v3 only",
        "summary": "No SNMP v1/v2c communities or traps; monitoring uses SNMPv3 users with authentication and encryption.",
        "about": (
            "SNMP v1 and v2c authenticate with a community string sent in clear text, and give read (or write) access "
            "to the appliance's configuration and counters to anyone who sees it. SNMPv3 users authenticate every "
            "request (SHA) and encrypt it (AES), so the monitoring traffic can neither be read nor forged."),
        "notes": [
            "Remove each community the appliance has (the dashboard lists them), and move traps to version 3.",
            "Without any SNMPv3 user the appliance simply is not monitored over SNMP - that also counts as in place.",
            "Give the monitoring system the same user, authentication and privacy passwords.",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("Remove the v1/v2c communities", "rm snmp community <COMMUNITY>"),
            ("An SNMPv3 user with authentication and encryption", "add snmp view SNMPv3_All_View 1 -type included\n"
             "add snmp group SNMPv3_Group authPriv -readViewName SNMPv3_All_View\n"
             "add snmp user <SNMP_USER> -group SNMPv3_Group -authType SHA -authPasswd <AUTH_PASSWORD> -privType AES -privPasswd <PRIV_PASSWORD>"),
            ("Traps over SNMPv3", "add snmp trap specific <TRAP_DESTINATION> -version V3 -userName <SNMP_USER>"),
        ]}],
        "detect": "snmp_v3",
    },
    {
        "id": "rpc_nodes",
        "group": "Management and platform",
        "title": "RPC nodes: changed password, secure channel",
        "summary": "The HA / cluster RPC channel uses its own password and is encrypted.",
        "about": (
            "HA and cluster nodes synchronise configuration and files over RPC. Its password is nsroot by default "
            "and the channel is not encrypted unless secure is set - anyone on the management network who knows "
            "the default can push configuration to the appliance."),
        "notes": [
            "The appliance never shows the RPC password, so the dashboard checks the secure channel only - make sure "
            "the password is not the default.",
            "Set the same password on every node of the pair.",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("For each node (its own and its peer's NSIP)", "set ns rpcNode <NSIP> -password <NEW_PASSWORD> -secure YES")]}],
        "detect": "rpc_nodes",
    },
    {
        "id": "admin_accounts",
        "group": "Management and platform",
        "title": "Named administrator accounts",
        "summary": "Administrators sign in with their own accounts, not all with nsroot.",
        "about": (
            "With one shared nsroot account nobody can tell who changed what, and the password has to change "
            "whenever someone leaves. Named accounts (best authenticated against the directory) make the audit log "
            "say who did it, and nsroot can be kept as a break-glass account with a long password."),
        "notes": ["The dashboard only sees which system users exist, not how they authenticate."],
        "variants": [{"label": "All versions", "commands": [
            ("A named administrator", "add system user <ADMIN_NAME> <PASSWORD>\nbind system user <ADMIN_NAME> superuser 100")]}],
        "detect": "admin_accounts",
    },
]
CHECKS.sort(key=lambda c: GROUP_ORDER.index(c["group"]))


# ------------------------------------------------------------ added in 1.22.0
CHECKS += [
    {
        "id": "http_extra",
        "group": "Gateway settings",
        "title": "Drop extra CRLF and extra data",
        "summary": "Stray line breaks between requests, and response data beyond Content-Length, are dropped.",
        "about": (
            "Extra CRLF between pipelined requests and response bodies longer than their Content-Length are the raw "
            "material of request smuggling and response splitting: they make the appliance and the server disagree "
            "on where one message ends and the next begins."),
        "notes": ["An HTTP profile bound to a virtual server overrides the default profile for it."],
        "variants": [{"label": "All versions", "commands": [
            ("Default HTTP profile", "set ns httpProfile nshttp_default_profile -dropExtraCRLF ENABLED -dropExtraData ENABLED")]}],
        "detect": "http_extra",
    },
    {
        "id": "trace_track",
        "group": "Gateway protection policies",
        "title": "Block TRACE and TRACK requests",
        "summary": "HTTP TRACE and TRACK requests are dropped before they reach anything.",
        "about": (
            "TRACE and TRACK echo the request back, headers included - with a cross-site scripting flaw that is a "
            "way to read cookies marked HttpOnly (cross-site tracing). Nothing behind a Gateway needs them."),
        "notes": [],
        "variants": [{"label": "All versions", "commands": [
            ("Responder policy, bound globally", "add responder policy Block_TRACE_TRACK_Policy \"HTTP.REQ.FULL_HEADER.STARTSWITH(\\\"TRACE \\\") || HTTP.REQ.FULL_HEADER.STARTSWITH(\\\"TRACK \\\")\" DROP\n"
             "bind responder global Block_TRACE_TRACK_Policy 110 END -type REQ_DEFAULT")]}],
        "policies": ["Block_TRACE_TRACK_Policy"],
        "signatures": [["trace", "track"]],
        "detect": "responder",
    },
    {
        "id": "geo_block",
        "group": "Gateway protection policies",
        "title": "Allow only the countries you serve (geolocation)",
        "summary": "Requests from countries outside an allowed list are dropped before the login page.",
        "about": (
            "Most password spraying and scanning against a Gateway comes from countries its users never connect "
            "from. With the location database NetScaler ships, a responder policy drops every request whose source "
            "address is not in the allowed countries - internal networks excepted, since private addresses have "
            "no location."),
        "notes": [
            "Only if your users connect from known countries - otherwise mark it 'Not relevant'.",
            "Add a country with another MATCHES_LOCATION(...) condition joined by ||, and keep your internal "
            "networks in the IN_SUBNET exception (more than one: join them with ||).",
            "Travelling users are refused in other countries; a VPN egress in an allowed country gets through.",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("The built-in location database", "add locationFile /var/netscaler/inbuilt_db/Citrix_Netscaler_InBuilt_GeoIP_DB_IPv4 -format netscaler"),
            ("Responder policy (country codes as in IL, US, DE)",
             "add responder policy Geo_Allowed_Countries_Policy \"CLIENT.IP.SRC.MATCHES_LOCATION(\\\"*.<COUNTRY_CODE>.*.*.*.*\\\").NOT && CLIENT.IP.SRC.IN_SUBNET(<INTERNAL_NETWORK>).NOT\" DROP"),
            ("Bind to the Gateway (AAA request)",
             "bind vpn vserver <GATEWAY_VSERVER> -policy Geo_Allowed_Countries_Policy -priority 90 -gotoPriorityExpression END -type AAA_REQUEST"),
        ]}],
        "policies": ["Geo_Allowed_Countries_Policy"],
        "signatures": [["matches_location"]],
        "detect": "geo",
        "optional": True,
    },
    {
        "id": "mgmt_acl",
        "group": "Management and platform",
        "title": "Management access limited by ACLs",
        "summary": "Only the administrators' networks (and this dashboard) can reach the management address.",
        "about": (
            "Secure-only HTTPS and strong passwords still let anyone on the network try. Extended ACLs on the "
            "management address allow the administrators' networks, this dashboard and the HA peer, and deny "
            "everyone else - the GUI, NITRO and SSH are then unreachable from anywhere else."),
        "notes": [
            "Allow the dashboard and the HA peer, or the dashboard stops reading the node and HA stops synchronising.",
            "ACLs take effect only after `apply ns acls`. Try it from the console, where a mistake can be undone "
            "(`rm ns acl Deny_Mgmt_Others` then `apply ns acls`).",
            "An address range is written as 192.0.2.10-192.0.2.50.",
        ],
        "variants": [{"label": "All versions", "commands": [
            ("Allow the administrators, the dashboard and the HA peer; deny the rest",
             "add ns acl Allow_Mgmt_Admins ALLOW -srcIP = <ADMIN_NETWORK> -destIP = <NSIP> -priority 10\n"
             "add ns acl Allow_Mgmt_Dashboard ALLOW -srcIP = <DASHBOARD_ADDRESS> -destIP = <NSIP> -priority 20\n"
             "add ns acl Allow_Mgmt_HA_Peer ALLOW -srcIP = <PEER_NSIP> -destIP = <NSIP> -priority 30\n"
             "add ns acl Deny_Mgmt_Others DENY -destIP = <NSIP> -priority 1000\n"
             "apply ns acls"),
        ]}],
        "detect": "mgmt_acl",
    },
]
CHECKS.sort(key=lambda c: GROUP_ORDER.index(c["group"]))
