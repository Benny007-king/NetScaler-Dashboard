"""Tests for the LDAP "allowed group" rule: a full DN means exactly that group.

    python tests/test_ldap_group.py   # needs the app's Python packages; no directory server
"""
import os
import sys
import tempfile

os.environ.update(DATA_DIR=tempfile.mkdtemp(), APP_SSL="0")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app   # noqa: E402


class Attr:
    def __init__(self, vals): self.values = vals; self.raw_values = vals


class Entry:
    def __init__(self, memberof): self.memberOf = Attr(memberof)


class PlainFinder:
    """A directory without AD's tokenGroups: every search comes back empty."""
    entries = []
    def search(self, *a, **k): self.entries = []; return True


class Obj:
    def __init__(self, **kw): self.__dict__.update(kw)


class ADFinder:
    """An AD-like directory with two groups that share a CN in different OUs."""
    GROUPS = {"cn=netscaler-admins,ou=groups,dc=corp,dc=example,dc=com": b"SID-RIGHT",
              "cn=netscaler-admins,ou=otherdept,dc=corp,dc=example,dc=com": b"SID-OTHER"}

    def __init__(self, user_sids): self.user_sids, self.entries, self.calls = user_sids, [], []

    def search(self, base, flt, search_scope=None, attributes=None):
        self.calls.append((base, flt, attributes))
        self.entries = []
        if attributes == ["objectSid"]:
            if "cn=" in flt.lower() and base.lower().startswith("dc="):      # lookup by name: the directory's first hit
                self.entries = [Obj(objectSid=Attr([b"SID-OTHER"]))]
            else:                                                            # lookup of that exact DN
                sid = self.GROUPS.get(app._dn_norm(base))
                self.entries = [Obj(objectSid=Attr([sid]))] if sid else []
        elif attributes == ["tokenGroups"]:
            self.entries = [Obj(tokenGroups=Attr(self.user_sids))]
        return True


cfg = {"base_dn": "DC=corp,DC=example,DC=com"}
RIGHT = "CN=NetScaler-Admins,OU=Groups,DC=corp,DC=example,DC=com"
OTHER = "CN=NetScaler-Admins,OU=OtherDept,DC=corp,DC=example,DC=com"
bad = 0


def check(got, want, what):
    global bad
    ok = got == want
    bad += not ok
    print("   %s  %s (%s)" % ("ok   " if ok else "FAIL ", what, "allowed" if got else "refused"))


def member(finder, memberof, allowed):
    return app._ldap_user_in_group(finder, "CN=bob,OU=Users,DC=corp,DC=example,DC=com", Entry(memberof), allowed, cfg)


print("-- a directory without tokenGroups (memberOf comparison)")
check(member(PlainFinder(), [RIGHT], RIGHT), True, "member of exactly the allowed group")
check(member(PlainFinder(), [OTHER], RIGHT), False, "member of a group with the same name in another OU")
check(member(PlainFinder(), ["cn=netscaler-admins , ou=Groups,dc=CORP,dc=example,dc=com"], RIGHT), True, "same DN written with other case and spacing")
check(member(PlainFinder(), ["CN=Domain Users,CN=Users,DC=corp,DC=example,DC=com"], RIGHT), False, "member of an unrelated group")
check(member(PlainFinder(), [OTHER], "NetScaler-Admins"), True, "only a group NAME configured: any group of that name (as documented)")
check(member(PlainFinder(), [], ""), True, "no allowed group configured: every directory user")
print("-- Active Directory (tokenGroups)")
check(member(ADFinder([b"SID-RIGHT"]), [], RIGHT), True, "user's token holds the allowed group's SID")
check(member(ADFinder([b"SID-OTHER"]), [], RIGHT), False, "user's token holds only the same-named group in another OU")
print("\n%s" % ("all LDAP group checks passed" if not bad else "%d FAILED" % bad))
sys.exit(1 if bad else 0)
