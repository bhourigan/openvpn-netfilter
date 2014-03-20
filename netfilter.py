#!/usr/bin/env python
# Requires:
# python-ldap
#
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is the netfilter.py for OpenVPN learn-address.
#
# The Initial Developer of the Original Code is
# Mozilla Corporation
# Portions created by the Initial Developer are Copyright (C) 2012
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
# gdestuynder@mozilla.com (initial author)
# jvehent@mozilla.com (refactoring, ipset support)
# bhourigan@mozilla.com (refactoring, ssh support)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.

import os
import sys
import ldap
import syslog
import pprint
import subprocess
from optparse import OptionParser

LDAP_URL='ldap://<%= ldap_server %>'
LDAP_BIND_DN='uid=<%= bind_user %>,ou=logins,dc=mozilla'
LDAP_BIND_PASSWD='<%= bind_password %>'
LDAP_BASE_DN='dc=mozilla'
LDAP_FILTER='cn=vpn_*'

CEF_FACILITY=syslog.LOG_LOCAL4
NODENAME=os.uname()[1]
IPTABLES='/sbin/iptables'
IPSET='/usr/sbin/ipset'
RULESCLEANUP='<%= confdir %>/plugins/netfilter/vpn-netfilter-cleanup-ip.sh'
RULES='<%= confdir %>/plugins/netfilter/rules'
TESTMODE=0
MAXCOMMENTLEN=254

def log(msg):
    """
        Send a message to syslog
    """
    syslog.openlog('OpenVPN', 0, syslog.LOG_DAEMON)
    syslog.syslog(syslog.LOG_INFO, msg)
    syslog.closelog()

def cef(msg1, msg2):
    """
        Build a log message in CEF format and send it to syslog
    """
    syslog.openlog('OpenVPN', 0, CEF_FACILITY)
    cefmsg = 'CEF:{v}|{deviceVendor}|{deviceProduct}|{deviceVersion}|{name}|{message}|{deviceSeverity}|{ext}'.format(
        v='0',
        deviceVendor='Mozilla',
        deviceProduct='OpenVPN',
        deviceVersion='1.0',
        name=msg1,
        message=msg2,
        deviceSeverity='5',
        ext=' dhost=' + NODENAME,
    )
    syslog.syslog(syslog.LOG_INFO, cefmsg)
    syslog.closelog()

def nf_exec(cmd, args):
    """
        Execute a arbitrary command (iptables, ipset) with accompanying arguments
        on the local system.

        Abort (exit) on failed execution. If TESTMODE=True then it always returns
        False
    """
    command = "%s %s" % (cmd, args)
    DEVNULL = open(os.devnull, 'wb')

    if TESTMODE:
        print("Command: %s (noop)" % command)
        return False

    try:
        status = subprocess.call(command, stdout=DEVNULL, stderr=DEVNULL, shell=True)
    except:
        print("Failed to execute iptables (%s)" % command)
        sys.exit(1)

    if status:
        return False
    return True

def iptables(args):
    return nf_exec(IPTABLES, args)

def ipset(args):
    return nf_exec(IPSET, args)

def iptables_chain_exists(name):
    """
        Test for existence of a chain via the iptables binary
    """
    if TESTMODE:
        return False
    return iptables('-L ' + name)

def ipset_nethash_exists(name):
    """
        Test for existence of a chain via the ipset binary
    """
    if TESTMODE:
        return False
    return ipset('list %s' % name)

def ldap_uid_to_mail(uid):
    """
        Query the LDAP directory and map a uid to a mail attribute
    """
    conn = ldap.initialize(LDAP_URL)
    conn.simple_bind_s(LDAP_BIND_DN, LDAP_BIND_PASSWD)

    res = conn.search_s(LDAP_BASE_DN, ldap.SCOPE_SUBTREE, '(uid=%s)' % uid, ['mail'])
    return res[0][1]['mail'][0]

def ldap_validate_mail(mail):
    """
        Query the LDAP directory and ensure that the mail is valid
    """
    conn = ldap.initialize(LDAP_URL)
    conn.simple_bind_s(LDAP_BIND_DN, LDAP_BIND_PASSWD)

    res = conn.search_s(LDAP_BASE_DN, ldap.SCOPE_SUBTREE, '(mail=%s)' % mail, ['mail'])
    return res[0][1]['mail'][0]

def ldap_query_vpn_groups(mail):
    """
        Query the LDAP directory and return a full list of VPN groups. We don't filter
        by user dn in the query since the format can vary. We just pull all groups and
        filter locally.

        Filtered results are stripped and parsed into a dictionary

        Returns: a sdictionary of the form
        schema = {'vpn_group1':
                {'networks':
                    ['192.168.0.1/24',
                    '10.0.0.1/16:80 #comment',
                    '10.0.0.1:22']
                },
            'vpn_group2': ...
        }
    """
    conn = ldap.initialize(LDAP_URL)
    conn.simple_bind_s(LDAP_BIND_DN, LDAP_BIND_PASSWD)
    res = conn.search_s('ou=groups,' + LDAP_BASE_DN, ldap.SCOPE_SUBTREE, LDAP_GROUP_FILTER, ['cn', 'member', 'ipHostNumber'])

    groups = {}
    for group in res:
        members = []
        networks = []
        name = group[1]['cn'][0]

        for member in group[1]['member']:
            try:
                members.append(member.split('=')[1].split(',')[0])
            except IndexError:
                log("Failed to load user from LDAP: %s at group %s, skipping" % (member, name))

        if 'ipHostNumber' in group[1]:
            networks = group[1]['ipHostNumber']

        if mail in members:
            groups[name] = {'networks': networks}

    return groups

def local_query_user_rules(mail):
    """
        Load destination IPs from a flat file that exists on the VPN gateway,
        and create the firewall rules accordingly.
        This feature does not use LDAP at all.

        This feature is rarely used, and thus the function will simply exit
        in silence if no file is found.
    """
    groups = {}
    networks = []
    path = os.path.join(RULES, mail)

    try:
        with open(path, "r") as handle:
            for line in handle:
                if line and not line.startswith('#'):
                    networks.append(line.split('\n')[0])
    except IOError:
        return groups

    groups['local'] = {'networks': networks}
    return groups

def netfilter_parse_network(group, networks, mail, options, chain, destinations):
    """
        Iteriate through indvidual rule dicts and construct the iptables commands
        to apply them.
    """

    for network in networks:
        ipHostNumber = network.split('#')
        destination = ipHostNumber[0].strip()

        if destination in destinations:
            # Skip duplicate destination addresses
            continue

        destinations.append(destination)

        comment = '%s:%s' % (mail, group)
        if len(ipHostNumber) > 1:
            comment += ' %s' % ipHostNumber[1]

        if options.ssh:
            match = '-m owner --uid-owner %s' % options.user
        else:
            match = '-s %s' % options.ip

        dest = destination.split(':')
        if len(dest) > 1:
            iptables('-A %s %s -d %s -p tcp -m multiport --dports %s -m comment --comment "%s" -j ACCEPT' % (chain, match, dest[0], dest[1], comment))
            iptables('-A %s %s -d %s -p udp -m multiport --dports %s -m comment --comment "%s" -j ACCEPT' % (chain, match, dest[0], dest[1], comment))
        else:
            ipset('--add %s %s' % (chain, dest[0]))

def netfilter_apply_rules(rules, mail, options):
    """
        Apply "glue" rules and iteriate through the dict list that was pulled
        from LDAP and built based on local files.
    """

    if options.ssh:
        chain = mail
        comment = '%s: via ssh' % mail
    if options.vpn:
        chain = options.ip
        comment = '%s @ %s' % (mail, options.ip)

    if not TESTMODE and iptables_chain_exists(chain):
        return

    if len(comment) > MAXCOMMENTLEN:
        comment = comment[:243] + '..truncated...'

    iptables('-N %s' % chain)
    ipset('--create %s nethash' % chain)

    destinations = list()
    for rule in rules:
        netfilter_parse_network(group=rule, networks=rules[rule]['networks'], mail=mail, options=options, chain=chain, destinations=destinations)

    if options.ssh:
        # If you add rules here, add a corresponding remove rule in netfilter_remove_rules below
        iptables('-A OUTPUT -m owner --uid-owner %s -j %s' % (options.user, chain))
        # Match packets owned by options.user and destined for an address listed in the ipset nethash for this user
        iptables('-I %s -m owner --uid-owner %s -m set --match-set %s dst -j ACCEPT -m comment --comment "%s"' % (chain, options.user, chain, comment))
    else:
        # If you add rules here, add a corresponding remove rule in netfilter_remove_rules below
        iptables('-A OUTPUT -d %s -j %s' % (options.ip, chain))
        iptables('-A INPUT -s %s -j %s' % (options.ip, chain))
        iptables('-A FORWARD -s %s -j %s' % (options.ip, chain))
        # Match packets owned by options.user and destined for an address listed in the ipset nethash for this user
        iptables('-I %s -m owner --uid-owner %s -m set --match-set %s dst -j ACCEPT -m comment --comment "%s"' % (chain, options.ip, chain, comment))

    # Establish matching inbound rules for outbound packets
    iptables('-I %s -m conntrack --ctstate ESTABLISHED -j ACCEPT -m comment --comment "%s"' % (chain, comment))

    # Log & drop the reset
    iptables('-A %s -j LOG --log-prefix "DROP %s" -m comment --comment "%s"' % (chain, mail[:23], comment))
    iptables('-A %s -j DROP -m comment --comment "%s"' % (chain, comment))

def netfilter_remove_rules(mail, options):
    """
        Remove all rules for an associated netfilter chain (either uid or mail)
    """

    if options.ssh:
        chain = mail
    if options.vpn:
        chain = options.ip

    if iptables_chain_exists(chain):
        if options.ssh:
            iptables('-D OUTPUT -m owner --uid-owner %s -j %s' % (options.user, chain))
        else:
            iptables('-D OUTPUT -d %s -j %s' % (options.ip, chain))
            iptables('-D INPUT -s %s -j %s' % (options.ip, chain))
            iptables('-D FORWARD -s %s -j %s' % (options.ip, chain))

        iptables('-F %s' % chain)
        iptables('-X %s' % chain)

    if ipset_nethash_exists(chain):
        ipset('destroy %s' % chain)

def main():
    """
        Main function, arguments documented in option parser below
    """
    global TESTMODE

    parser = OptionParser()
    parser.add_option("-a", "--apply", dest="apply", action="store_true", default=False, help="apply netfilter rules for USER")
    parser.add_option("-i", "--ip", dest="ip", default=False, help="USER's source IP address when connected to VPN", metavar="IP")
    parser.add_option("-r", "--remove", dest="remove", action="store_true", default=False, help="remove netfilter rules for USER")
    parser.add_option("-s", "--ssh", dest="ssh", action="store_true", default=False, help="apply or remove rules for local user USER")
    parser.add_option("-t", "--test", dest="test", action="store_true", default=False, help="enable test mode, no rules are modified")
    parser.add_option("-u", "--user", dest="user", default=False, help="configure rules for user USER. local username with --ssh, mail with --vpn", metavar="USER")
    parser.add_option("-v", "--vpn", dest="vpn", action="store_true", default=False, help="apply or remove rules for vpn user USER")
    (options, args) = parser.parse_args()
    TESTMODE = options.test

    if not bool(options.apply) ^ bool(options.remove):
        print("You are required to specify either --apply or --remove")
        sys.exit(1)

    if not bool(options.ssh) ^ bool(options.vpn):
        print("You are required to specify either --ssh or --vpn")
        sys.exit(1)

    if options.ssh:
        if not options.user:
            print("A username is required when using --ssh")
            sys.exit(1)

        try:
            mail = ldap_uid_to_mail(options.user)
        except:
            print("Invalid ldap uid %s" % options.user)
            sys.exit(1)

    if options.vpn:
        if not options.user:
            print("A username (mail) is required when using --vpn")
            sys.exit(1)

        if not options.ip:
            print("A source IP address is required when using --vpn")
            sys.exit(1)

        try:
            mail = ldap_validate_mail(options.user)
        except:
            print("Invalid LDAP user %s" % options.user)
            sys.exit(1)

    if options.apply:
        if not TESTMODE:
            cef('User Login Successful|SSH user connected', 'mail=%s uid=%s' % (mail, options.user))

        ldap_vpn_groups = ldap_query_vpn_groups(mail)
        local_user_rules = local_query_user_rules(mail)

        netfilter_rules = dict(ldap_vpn_groups.items() + local_user_rules.items())
        netfilter_apply_rules(netfilter_rules, mail, options)

    if options.remove:
        if not TESTMODE:
            cef('User Logout Successful|SSH user disconnected', 'mail=%s uid=%s' % (mail, options.user))

        netfilter_remove_rules(mail, options)

    sys.exit(0)

if __name__ == "__main__":
    main()
