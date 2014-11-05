/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2011, 2013, 2014 Zimbra, Inc.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
 */
package com.zimbra.ldaputils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.Domain;
import com.zimbra.cs.account.NamedEntry;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.ldap.LdapObjectClass;
import com.zimbra.cs.account.ldap.LdapProv;
import com.zimbra.qa.unittest.TestLdap;
import com.zimbra.qa.unittest.TestUtil;

/* Posix/Samba tests currently ignored
 * To run:
 *
 * cp ~/p4/main/ZimbraSambaExtension/src/schema/samba.schema /opt/zimbra/openldap/etc/openldap/schema/samba.schema
 *
 * edit /opt/zimbra/conf/slapd.conf
 * add:
 * include         "/opt/zimbra/openldap/etc/openldap/schema/nis.schema"    (for posix account and grop)
 * include         "/opt/zimbra/openldap/etc/openldap/schema/samba.schema"  (for samba domain)
 *
 * then restart slapd
 *
 */

@Ignore("requires running ldap")
public class TestLDAPUtilsHelper extends TestLdap {

    private static LdapProv prov;
    private static Domain domain;
    private static String baseDN;

    @BeforeClass
    public static void init() throws Exception {
        prov = LdapProv.getInst();
        domain = prov.createDomain(baseDomainName(), new HashMap<String, Object>());
        baseDN = prov.getDIT().domainNameToDN(domain.getName());
    }

    @AfterClass
    public static void cleanup() throws Exception {
        String baseDomainName = baseDomainName();
        TestLdap.deleteEntireBranch(baseDomainName);
    }

    private static String baseDomainName() {
        return TestLDAPUtilsHelper.class.getName().toLowerCase();
    }

    private LDAPUtilEntry createEntry(String leafRDN) throws Exception {
        return createEntry(leafRDN, null);
    }

    private LDAPUtilEntry createEntry(String leafRDN, Map<String, Object> attrs) throws Exception {
        String dn = leafRDN + "," + baseDN;

        if (attrs == null) {
            attrs = new HashMap<String, Object>();
            attrs.put(Provisioning.A_objectClass, LdapObjectClass.ZIMBRA_DEFAULT_PERSON_OC);
            attrs.put("sn", "sn");
        }
        NamedEntry ne = LDAPUtilsHelper.getInstance().createLDAPEntry(dn,  attrs);

        assert(ne != null);
        assert(ne instanceof LDAPUtilEntry);
        LDAPUtilEntry ldapEntry = (LDAPUtilEntry) ne;
        assertEquals(dn, ldapEntry.getDN());

        return ldapEntry;
    }

    @Test
    public void createLDAPEntry() throws Exception {
        String leafRDN = "cn=createLDAPEntry";
        LDAPUtilEntry ldapEntry = createEntry(leafRDN);

        // create again
        boolean caughtException = false;
        try {
            ldapEntry = createEntry(leafRDN);
        } catch (ZimbraLDAPUtilsServiceException e) {
            if (ZimbraLDAPUtilsServiceException.DN_EXISTS.equals(e.getCode())) {
                caughtException = true;
            }
        }
        assertTrue(caughtException);
    }

    @Test
    public void deleteLDAPEntry() throws Exception {
        String leafRDN = "cn=deleteLDAPEntry";
        LDAPUtilEntry ldapEntry = createEntry(leafRDN);
        String dn = ldapEntry.getDN();

        LDAPUtilsHelper.getInstance().deleteLDAPEntry(dn);

        String query = "cn=deleteLDAPEntry";
        String sortBy = "cn";
        List<NamedEntry> entries = LDAPUtilsHelper.getInstance().searchObjects(
                query, baseDN, sortBy, true);

        assert(entries.size() == 0);

        // delete again
        /*
        boolean caughtException = false;
        try {
            LDAPUtilsHelper.getInstance().deleteLDAPEntry(dn);
        } catch (ServiceException e) {
            caughtException = true;
        }
        assertTrue(caughtException);
        */
    }

    @Test
    public void modifyLDAPEntry() throws Exception {
        String leafRDN = "cn=modifyLDAPEntry";
        LDAPUtilEntry ldapEntry = createEntry(leafRDN);
        String dn = ldapEntry.getDN();

        Map<String, Object> attrs = new HashMap<String, Object>();
        String attr = "sn";
        String newValue = "new value";
        attrs.put(attr, newValue);
        LDAPUtilEntry newLdapEntry = (LDAPUtilEntry) LDAPUtilsHelper.getInstance().modifyLDAPEntry(dn, attrs);

        String value = newLdapEntry.getAttr(attr);
        assertEquals(newValue, value);
    }

    @Test
    public void renameLDAPEntry() throws Exception {
        String leafRDN = "cn=renameLDAPEntry";
        LDAPUtilEntry ldapEntry = createEntry(leafRDN);
        String dn = ldapEntry.getDN();

        String newDN = "cn=renameLDAPEntry-renamed" + "," + baseDN;
        LDAPUtilEntry renamedLdapEntry = (LDAPUtilEntry) LDAPUtilsHelper.getInstance().renameLDAPEntry(dn, newDN);

        assertEquals(newDN, renamedLdapEntry.getDN());
    }

    @Test
    public void getLDAPEntry() throws Exception {
        String leafRDN1 = "cn=getLDAPEntry1";
        LDAPUtilEntry ldapEntry1 = createEntry(leafRDN1);

        String leafRDN2 = "cn=getLDAPEntry2";
        LDAPUtilEntry ldapEntry2 = createEntry(leafRDN2);

        String query = "cn=getLDAPEntry*";
        String sortBy = "cn";
        List<NamedEntry> entries = LDAPUtilsHelper.getInstance().searchObjects(
                query, baseDN, sortBy, true);

        assertEquals(2, entries.size());
        assertEquals("getLDAPEntry1", entries.get(0).getAttr("cn"));
        assertEquals("getLDAPEntry2", entries.get(1).getAttr("cn"));
    }

    @Test
    @Ignore
    public void posixAccount() throws Exception {
        String posixAccountIdAttr = "uidNumber";
        String posixAccountId = "123";
        Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put(Provisioning.A_objectClass, "posixAccount");
        attrs.put(posixAccountIdAttr, posixAccountId);
        attrs.put("gidNumber", "1234");
        attrs.put("homeDirectory", "homeDirectory");

        String email = TestUtil.getAddress("posixAccount", domain.getName());
        Account acct = prov.createAccount(email, "test123", attrs);

        String query = "uidNumber=123";
        String sortBy = posixAccountId;
        List<NamedEntry> entries = LDAPUtilsHelper.getInstance().searchObjects(
                query, baseDN, sortBy, true);

        assertEquals(1, entries.size());
        NamedEntry entry = entries.get(0);

        assertTrue(entry instanceof PosixAccount);
        PosixAccount posixAccount = (PosixAccount) entry;
        assertEquals(posixAccountId, posixAccount.getId());
    }

    @Test
    @Ignore
    public void posixGroup() throws Exception {
        String posixGroupIdAttr = "gidNumber";
        String posixGroupId = "123";

        String leafRDN = posixGroupIdAttr + "=" + posixGroupId;

        Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put(Provisioning.A_objectClass, "posixGroup");
        attrs.put(posixGroupIdAttr, posixGroupId);
        attrs.put("cn", "cn");

        LDAPUtilEntry ldapEntry = createEntry(leafRDN, attrs);

        String query = leafRDN;
        String sortBy = posixGroupIdAttr;
        List<NamedEntry> entries = LDAPUtilsHelper.getInstance().searchObjects(
                query, baseDN, sortBy, true);

        assertEquals(1, entries.size());
        NamedEntry entry = entries.get(0);

        assertTrue(entry instanceof PosixGroup);
        PosixGroup posixGroup = (PosixGroup) entry;
        assertEquals(posixGroupId, posixGroup.getId());
    }


    @Test
    @Ignore
    public void sambaDomain() throws Exception {
        String sambaDomainIdAttr = "sambaSID";
        String sambaDomainId = "123";
        String sambeDomainNameAttr = "sambaDomainName";
        String sambeDomainName = "samba.com";

        String leafRDN = sambeDomainNameAttr + "=" + sambeDomainName;

        Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put(Provisioning.A_objectClass, "sambaDomain");
        attrs.put(sambaDomainIdAttr, sambaDomainId);
        attrs.put(sambeDomainNameAttr, sambeDomainName);

        LDAPUtilEntry ldapEntry = createEntry(leafRDN, attrs);

        String query = leafRDN;
        String sortBy = sambeDomainNameAttr;
        List<NamedEntry> entries = LDAPUtilsHelper.getInstance().searchObjects(
                query, baseDN, sortBy, true);

        assertEquals(1, entries.size());
        NamedEntry entry = entries.get(0);

        assertTrue(entry instanceof SambaDomain);
        SambaDomain sambaDomain = (SambaDomain) entry;
        assertEquals(sambaDomainId, sambaDomain.getId());
        assertEquals(sambeDomainName, sambaDomain.getAttr(sambeDomainNameAttr));
    }

}
