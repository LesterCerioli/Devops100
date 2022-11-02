// SPDX-FileCopyrightText: 2022 Synacor, Inc.
// SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
//
// SPDX-License-Identifier: GPL-2.0-only

package com.zimbra.ldaputils;

import com.zimbra.common.localconfig.LC;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.cs.mailbox.OperationContext;
import java.util.Map;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.Element;
import com.zimbra.common.soap.LDAPUtilsConstants;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.NamedEntry;
import com.zimbra.cs.service.admin.AdminDocumentHandler;
import com.zimbra.cs.service.admin.AdminService;
import com.zimbra.soap.ZimbraSoapContext;

/**
 * @author Greg Solovyev
 */
public class CreateLDAPEntry extends AdminDocumentHandler {

    public Element handle(Element request, Map<String, Object> context)
    throws ServiceException {

        ZimbraSoapContext lc = getZimbraSoapContext(context);
        OperationContext operationContext = getOperationContext(lc, context);

        boolean allowAccess = LC.enable_delegated_admin_ldap_access.booleanValue();
        if(operationContext.getAuthToken().isDelegatedAdmin() && !allowAccess) {
            throw ServiceException.PERM_DENIED("Delegated admin can not modify LDAP");
        }

        String dn = request.getAttribute(LDAPUtilsConstants.E_DN);
        Map<String, Object> attrs = AdminService.getAttrs(request, true);

        NamedEntry ne = LDAPUtilsHelper.getInstance().createLDAPEntry(dn,  attrs);

        ZimbraLog.security.info(ZimbraLog.encodeAttrs(
                new String[] {"cmd", "CreateLDAPEntry","dn", dn}, attrs));

        Element response = lc.createElement(LDAPUtilsConstants.CREATE_LDAP_ENTRY_RESPONSE);
        ZimbraLDAPUtilsService.encodeLDAPEntry(response,ne);

        return response;
    }

}
