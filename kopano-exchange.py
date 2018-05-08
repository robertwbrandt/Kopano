#!/usr/bin/env python
"""
Python utility to monitor when LDAP attributes change and issue --sync command to Kopano
"""
import argparse, textwrap, fnmatch, datetime, urllib, json, re
import xml.etree.cElementTree as ElementTree
import subprocess

# Import Brandt Common Utilities
import sys, os
sys.path.append( os.path.realpath( os.path.join( os.path.dirname(__file__), "/opt/brandt/common" ) ) )
import brandt
sys.path.pop()

args = {}
args['config'] = '/etc/kopano/server.cfg'
args['force'] = False
args['minObjects'] = 800

version = 0.4

ADLDAP            = {}
ADLDAPURL         = ""
ADLDAPAttrAdd     = set(["objectclass","samaccountname","msExchGenericForwardingAddress","msExchHomeServerName"])
ADLDAPAttrIgnore  = set(["usnchanged","objectguid","grouptype","unicodepwd","usercertificate","usercertificate;binary","zarafabase"])
cacheFile         = "/tmp/kopano.ldap.cache"
postfixVTransport = "/etc/postfix/vtransport"

postfixVTransportHeader = """
# /etc/postfix/vtransport - Postfix virtual transport for Exchange
# this file configures virtual transport for Exchange only accounts (users & groups accounts)
# and for Kopano & Exchange accounts (users & groups accounts, no aliases exist)
administrators@opw.ie administrators@dublinnotes.opw.ie
notes.administrator@opw.ie  notes.administrator@dublinnotes.opw.ie
oireachtas.oireachtas@opw.ie  oireachtas.oireachtas@dublinnotes.opw.ie
#chaircorr@opw.ie chaircorr@dublinnotes.opw.ie
#eftpay@opw.ie  eftpay@dublinnotes.opw.ie
#enghatchst@opw.ie  enghatchst@dublinnotes.opw.ie
#investigate@opw.ie investigate@dublinnotes.opw.ie
#mailmeter@opw.ie mailmeter@dublinnotes.opw.ie
#mailsweeper@opw.ie mailsweeper@dublinnotes.opw.ie
#mcmahondiary@opw.ie  mcmahondiary@dublinnotes.opw.ie
#opwpeople@opw.ie opwpeople@dublinnotes.opw.ie
#opwstaff@opw.ie  opwstaff@dublinnotes.opw.ie
#postmaster@opw.ie  postmaster@dublinnotes.opw.ie
#btu@opw.ie btu@dublinnotes.opw.ie  btu@opw.ie
"""

exchangeLDAPFilter = "(&(msExchHomeServerName=*)(mail=*))"




class customUsageVersion(argparse.Action):
  def __init__(self, option_strings, dest, **kwargs):
    self.__version = str(kwargs.get('version', ''))
    self.__prog = str(kwargs.get('prog', os.path.basename(__file__)))
    self.__row = min(int(kwargs.get('max', 80)), brandt.getTerminalSize()[0])
    self.__exit = int(kwargs.get('exit', 0))
    super(customUsageVersion, self).__init__(option_strings, dest, nargs=0)
  def __call__(self, parser, namespace, values, option_string=None):
    # print('%r %r %r' % (namespace, values, option_string))
    if self.__version:
      print self.__prog + " " + self.__version
      print "Copyright (C) 2013 Free Software Foundation, Inc."
      print "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>."
      version  = "This program is free software: you can redistribute it and/or modify "
      version += "it under the terms of the GNU General Public License as published by "
      version += "the Free Software Foundation, either version 3 of the License, or "
      version += "(at your option) any later version."
      print textwrap.fill(version, self.__row)
      version  = "This program is distributed in the hope that it will be useful, "
      version += "but WITHOUT ANY WARRANTY; without even the implied warranty of "
      version += "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the "
      version += "GNU General Public License for more details."
      print textwrap.fill(version, self.__row)
      print "\nWritten by Bob Brandt <projects@brandt.ie>."
    else:
      print "Usage: " + self.__prog + " [options]"
      print "Python utility to monitor when LDAP attributes change and issue --sync command to Kopano.\n"
      print "Options:"
      options = []
      options.append(("-h, --help",          "Show this help message and exit"))
      options.append(("-v, --version",       "Show program's version number and exit"))
      options.append(("-c, --config CONFIG", "Kopano Configuration file (Default: " + args['config'] + ")"))
      options.append(("-f, --force",         "Force sync"))
      length = max( [ len(option[0]) for option in options ] )
      for option in options:
        description = textwrap.wrap(option[1], (self.__row - length - 5))
        print "  " + option[0].ljust(length) + "   " + description[0]
      for n in range(1,len(description)): print " " * (length + 5) + description[n]
    exit(self.__exit)
def command_line_args():
  global args, version
  parser = argparse.ArgumentParser(add_help=False)
  parser.add_argument('-v', '--version', action=customUsageVersion, version=version, max=80)
  parser.add_argument('-h', '--help', action=customUsageVersion)
  parser.add_argument('-c', '--config',
                      required=False,
                      default=args['config'],
                      type=str,
                      help="Kopano Configuration file")
  parser.add_argument('-f', '--force',
                      required=False,
                      default=args['force'],
                      action="store_true",
                      help="Force sync")
  args.update(vars(parser.parse_args()))


def get_kopano_LDAPURI():
  global args, ADLDAP, ADLDAPAttrAdd, ADLDAPAttrIgnore, exchangeLDAPFilter
  ldapConfig  = ""
  ldapPropMap = ""
  kopanoAttrs = ADLDAPAttrAdd
  LDAPFilter  = exchangeLDAPFilter

  f = open(args['config'], 'r')
  out = f.read()
  f.close()
  for line in out.split('\n'):
    if str(line)[:18].lower() == "user_plugin_config":
      line = line.split("=",1)
      if len(line) == 2: 
        ldapConfig = str(line[1]).strip()
        break

  f = open(ldapConfig, 'r')
  out = f.read()
  f.close()
  for line in out.split('\n'):
    if str(line)[:9].lower() == "!propmap ":
      ldapPropMap = str(line.split(" ",1)[1]).strip()
      continue

    if line and str(line)[0] not in ['#',';']:
      line = line.split("=",1)
      if len(line) == 2 and line[1].strip(): 
        ADLDAP[str(line[0]).strip().lower()] = str(line[1]).strip()

  f = open(ldapPropMap, 'r')
  out = f.read()
  f.close()
  for line in out.split('\n'):
    if line and str(line)[0] not in ['#',';']:
      line = line.split("=",1)
      if len(line) == 2 and line[1].strip(): 
        kopanoAttrs.add(str(line[1]).strip().lower())

  for key in ADLDAP.keys():
    if key[-9:] == 'attribute':
      kopanoAttrs.add(ADLDAP[key].lower())
  kopanoAttrs -= ADLDAPAttrIgnore

  for key in ADLDAP.keys():
    if key[-6:] == 'filter':
      LDAPFilter += ADLDAP[key]
  LDAPFilter = "(|" + LDAPFilter +")"

  ADLDAPURI = ADLDAP.get('ldap_uri','').split(" ")[0]
  if not ADLDAPURI:
    ADLDAPURI = ADLDAP.get('ldap_protocol','ldap') + '://' + ADLDAP.get('ldap_host','')
    if ADLDAP.has_key('ldap_port'): ADLDAPURI += ':' + ADLDAP['ldap_port']
  if ADLDAPURI[-1] != "/": ADLDAPURI += '/'
  if ADLDAP.has_key('ldap_search_base'): ADLDAPURI += urllib.quote(ADLDAP['ldap_search_base'])
  ADLDAPURI += "?" + urllib.quote(",".join(sorted(kopanoAttrs)))
  ADLDAPURI += "?sub"
  ADLDAPURI += "?" + LDAPFilter
  if ADLDAP.has_key('ldap_bind_user'): ADLDAPURI += "?bindname=" + urllib.quote(ADLDAP['ldap_bind_user']) + ",X-BINDPW=" + urllib.quote(ADLDAP.get('ldap_bind_passwd',""))

  return ADLDAPURI

def get_ldap(LDAPURI):
  # try:
    return brandt.LDAPSearch(LDAPURI).resultsDict(functDN=lambda dn: brandt.strXML(brandt.formatDN(dn)),
                                                  functAttr=lambda a: brandt.strXML(str(a).lower()), 
                                                  functValue=lambda *v:brandt.strXML(brandt.formatDN(v[-1])))
  # except:
  #   return {}

def read_cache_file(filename):
  try:
    return json.load(open(filename,'r'))
  except:
    return {}

def write_cache_file(filename, data):
  json.dump(data, open(filename, 'w'), sort_keys=True, indent=2)

def cmpDict(dict1, dict2):
  global args,output

  try:  
    if set(dict1.keys()) != set(dict2.keys()): 
      output += "Changes Found:\n"
      if bool(set(dict1.keys()) - set(dict2.keys())):
        output += "New DNs: " + ", ".join(list(set(dict1.keys()))) + "\n"
      if bool(set(dict2.keys()) - set(dict1.keys())):
        output += "Removed DNs: " + ", ".join(list(set(dict2.keys()))) + "\n"
      return False
    for dn in dict1.keys():
      if sorted(dict1[dn].keys()) != sorted(dict2[dn].keys()):
        output += "Changes Found:\n"
        if bool(set(dict1[dn].keys()) - set(dict2[dn].keys())):
          output += "New Attribute for (" + str(dn) + "): " + ", ".join(list(set(dict1[dn].keys()))) + "\n"
        if bool(set(dict2[dn].keys()) - set(dict1[dn].keys())):
          output += "Removed Attribute for (" + str(dn) + "): " + ", ".join(list(set(dict2[dn].keys()))) + "\n"
        return False
      for attr in dict1[dn].keys():
        if sorted(dict1[dn][attr]) != sorted(dict2[dn][attr]):
          output += "Changes Found:\n"
          output += "Value of Attribute(" + str(attr) + ") for (" + str(dn) + "):\n"
          output += "Old: " + ", ".join(sorted(dict2[dn][attr])) + "\n"
          output += "New: " + ", ".join(sorted(dict1[dn][attr])) + "\n"
          return False
  except:
    return False
  return True

def ordered(obj):
  if isinstance(obj, dict):
    return sorted((k, ordered(v)) for k, v in obj.items())
  if isinstance(obj, list):
    return sorted(ordered(x) for x in obj)
  else:
    return obj

def get_data(LDAPURI):
  global args, output

  date = datetime.datetime.now()
  liveData = get_ldap(LDAPURI)

  if len(liveData) < args['minObjects']:
    tmp = "Unable to get reliable Active Directory Download. Only " + str(len(liveData)) + " objects."
    tmp += '\n' + str(LDAPURI)
    raise IOError, tmp

  changed = True
  cachedData = read_cache_file(cacheFile)
  date = None
  if cachedData:
    date = datetime.datetime.fromtimestamp(os.stat(cacheFile).st_mtime)
    changed = not ( ordered( cachedData ) == ordered( liveData ) )
  if changed: write_cache_file(cacheFile,liveData)

  # if not cachedData or not args['web']:
  #   kopanoCache = read_cache_file(cacheFile)
  #   output += "Checking Kopano entries\n"
  #   if not cmpDict(kopanoLive, kopanoCache):
  #     output += "Kopano entries have changed\n"
  #     write_cache_file(cacheFile,kopanoLive)
  #     kopanoChanged = True
  #   cachedData = {}
  #   for account in kopanoLive.keys():
  #     for mail in kopanoLive[account].get('mail',[]) + kopanoLive[account].get('othermailbox',[]):
  #       objectclass = set([ str(x).lower() for x in kopanoLive[account].get('objectclass',[]) ])
  #       cachedData[mail] = {'kopano':True, 
  #                               'domino':False, 
  #                               'forward':False, 
  #                               'type':'', 
  #                               'username':str(kopanoLive[account].get('samaccountname',[''])[0])}
  #       if bool(set(["group","dominogroup","groupofnames"]) & objectclass):
  #         cachedData[mail]['type'] = "Group"
  #       elif bool(set(["person","user","dominoperson","inetorgperson","organizationalperson"]) & objectclass):
  #         cachedData[mail]['type'] = "User"
  #       else:
  #         cachedData[mail]['type'] = ",".join(sorted(objectclass))
  #   write_cache_file(cacheFile,cachedData)

  return (changed, date, liveData)

# Start program
if __name__ == "__main__":
  # try:
    output = ""
    error = ""
    exitcode = 0    

    command_line_args()
    changed, date, data = get_data( get_kopano_LDAPURI() )

    if changed or args['force']:
      print "Run Kopano Sync"
      # output += brandt.syslog("Changes detected: Running Kopano Sync\n", options=['pid'])
      # command = '/usr/sbin/kopano-admin --sync'
      # p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      # out, err = p.communicate()
      # if err: raise IOError(err)
      # output += out + "\n"



      vTransport = str(postfixVTransportHeader).strip()
      vTransportUsers=[]
      # Find Exchnage user who do NOT have forwarding turned on.
      for user in data:
        if data[user].has_key("msexchhomeservername"):
          if not data[user].has_key("msexchgenericforwardingaddress"):
            if data[user].has_key("mail"):
              vTransportUsers += data[user]["mail"]

      for user in sorted(vTransportUsers):
        exchange = str(user).lower().replace("@opw.ie","@exchange.opw.ie")
        if str(user).lower() != exchange:
          vTransport += "\n" + user + "\t" + exchange

      f = open(postfixVTransport, 'r')
      out = f.read()
      f.close()
      changed = ( out != vTransport )

      if changed or args['force']: 
        print "Reload Postfix"




  #   if args['web']:
  #     xmldata = ElementTree.Element('emails', **{'date': brandt.strXML(datetime.datetime.strftime(date,'%Y-%m-%d %H:%M:%S'))})
  #     for email in sorted(emails.keys()):
  #       ElementTree.SubElement(xmldata, 'email', **{'mail': brandt.strXML(email), 
  #                                       'kopano': brandt.strXML(emails[email]['kopano']), 
  #                                       'domino': brandt.strXML(emails[email]['domino']), 
  #                                       'forward': brandt.strXML(emails[email]['forward']),
  #                                       'username': brandt.strXML(emails[email]['username']),
  #                                       'type': brandt.strXML(emails[email]['type'])})
  #   else:
  #     if kopanoChanged or args['force']:
  #       output += brandt.syslog("Changes detected: Running Kopano Sync\n", options=['pid'])
  #       command = '/usr/sbin/kopano-admin --sync'
  #       p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  #       out, err = p.communicate()
  #       if err: raise IOError(err)
  #       output += out + "\n"

  #     reloadPostfix = False

  #     f = open(postfixBCC, 'r')
  #     out = f.read().split('\n')
  #     f.close()
  #     oldFile = set([])
  #     for line in out:
  #       if line and not line[0] in ["#",";"]:
  #         oldFile.add(line.split()[0].lower())
  #     newFile = set([ k for k in emails.keys() if (emails[k]['type'] == "User") and emails[k]['kopano'] and ( emails[k]['domino'] == emails[k]['forward'] ) ])
  #     output += "Checking Postfix BCC entries\n"
  #     if len(oldFile ^ newFile) or args['force']:
  #       reloadPostfix = True
  #       tmp = "Changes detected: Rebuilding Postfix BCC file for Mailmeter\n"
  #       tmp += "Removed BCC emails:" + ", ".join(sorted(oldFile - newFile)) + "\n"
  #       tmp += "Added BCC emails:" + ", ".join(sorted(newFile - oldFile)) + "\n"
  #       output += brandt.syslog(tmp, options=['pid'])

  #       tmp = "# /etc/postfix/bcc - OPW Postfix BCC Mapping for Kopano Only users\n"
  #       for mail in sorted(newFile):
  #         tmp += mail + "\tarchive@mailmeter.opw.ie\n"
  #       f = open(postfixBCC, 'w')
  #       f.write(tmp)
  #       f.close()

  #     f = open(postfixVTransport, 'r')
  #     out = f.read().split('\n')
  #     f.close()
  #     oldFile = {}
  #     for line in out:
  #       if line and not line[0] in ["#",";"]:
  #         tmp = str(line).lower().split()
  #         oldFile[tmp[0]] = sorted([ x.strip() for x in tmp[1:] if x.strip() ])
  #     newFile = {}
  #     for mail in sorted(emails.keys()):
  #       if emails[mail]['domino'] and not emails[mail]['forward']:
  #         newFile[mail] = [ re.sub('@opw.ie$','@dublinnotes.opw.ie',mail) ]
  #         if emails[mail]['kopano']: newFile[mail].append(mail)
  #         newFile[mail] = sorted(newFile[mail])
  #     output += "Checking Postfix vTransport entries\n"
  #     same = bool( set(oldFile.keys()) == set(newFile.keys()) )
  #     if same:
  #       for mail in oldFile.keys():
  #         same = bool( oldFile[mail] == newFile[mail] )
  #         if not same: break
  #     if not same or args['force']:
  #       reloadPostfix = True
  #       tmp = "Changes detected: Rebuilding Postfix vTransport file for Smarthost\n"
  #       tmp += "Removed vTransport emails:" + ", ".join(sorted(set(oldFile.keys()) - set(newFile.keys()))) + "\n"
  #       tmp += "Added vTransport emails:" + ", ".join(sorted(set(newFile.keys()) - set(oldFile.keys()))) + "\n"
  #       output += brandt.syslog(tmp, options=['pid'])

  #       tmp = "# /etc/postfix/vtransport - OPW Postfix virtual transport for Lotus Notes\n"
  #       tmp += "# this file configures virtual transport for Lotus Notes only accounts (users & groups accounts)\n"
  #       tmp += "# and for Kopano & Lotus notes accounts (users & groups accounts, no aliases exist)\n"
  #       for mail in sorted(newFile.keys()):
  #         tmp += mail + "\t" + "\t".join(newFile[mail]) + "\n"
  #       f = open(postfixVTransport, 'w')
  #       f.write(tmp)
  #       f.close()

  #     if reloadPostfix or args['force']:
  #       output += brandt.syslog("Rebuilding Postmaps\n", options=['pid'])
  #       command = '/usr/sbin/postmap ' + postfixBCC 
  #       p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  #       out, err = p.communicate()
  #       if err: raise IOError(err)
  #       output += out + "\n"

  #       command = '/usr/sbin/postmap ' + postfixVTransport 
  #       p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  #       out, err = p.communicate()
  #       if err: raise IOError(err)
  #       output += out + "\n"

  #       output += brandt.syslog("Reloading Postfix\n", options=['pid'])
  #       command = 'service postfix reload'
  #       p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  #       out, err = p.communicate()
  #       if err: raise IOError(err)
  #       output += out + "\n"

  # except SystemExit as err:
  #   pass
  # except Exception as err:
  #   try:
  #     exitcode = int(err[0])
  #     errmsg = str(" ".join(err[1:]))
  #   except:
  #     exitcode = -1
  #     errmsg = str(err)

  #   if args['web']: 
  #     error = "(" + str(exitcode) + ") " + str(errmsg) + "\nCommand: " + " ".join(sys.argv)
  #   else:
  #     xmldata = ElementTree.Element('error', code=brandt.strXML(exitcode), 
  #                                            msg=brandt.strXML(errmsg), 
  #                                            cmd=brandt.strXML(" ".join(sys.argv)))
  # finally:
  #   if not args['web']: 
  #     if output: print str(output)
  #     if error:  sys.stderr.write( str(error) + "\n" )
  #   else:    
  #     xml = ElementTree.Element('kopanoadmin')
  #     xml.append(xmldata)
  #     print '<?xml version="1.0" encoding="' + encoding + '"?>\n' + ElementTree.tostring(xml, encoding=encoding, method="xml")
  #   sys.exit(exitcode)
