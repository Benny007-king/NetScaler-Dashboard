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
        "group": "Appliance hardening",
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
        "group": "Appliance hardening",
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
        "group": "Appliance hardening",
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
        "group": "Appliance hardening",
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
        "group": "Appliance hardening",
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
        "group": "Appliance hardening",
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
        "group": "Appliance hardening",
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
