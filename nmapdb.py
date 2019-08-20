#!/usr/bin/env python
#
# nmapdb - Parse nmap's XML output files and insert them into an SQLite database
# Copyright (c) 2012 Patroklos Argyroudis <argp at domain census-labs.com>

import sys
import os
import getopt
import xml.dom.minidom
from pysqlite2 import dbapi2 as sqlite

VERSION = "1.2"
DEFAULT_DATABASE = "./nmapdb.db"

true = 1
false = 0
vflag = false

def myprint(msg):
    global vflag
    if vflag == true:
        print msg

    return

def usage(name):
    print "usage: %s [options] <nmap output XML file(s)>" % name
    print "options:"
    print "     (-h) --help         this message"
    print "     (-v) --verbose      verbose output"
    print "     (-c) --create       specify input SQL file to create SQLite DB"
    print "     (-d) --database     specify output SQLite DB file"
    print "     (-f) --frequency    list most frequent open ports from specified DB"
    print "     (-n) --nodb         do not perform any DB operations (i.e. dry run)"
    print "     (-V) --version      output version number and exit"

    return

def dict_factory(cursor, row):
    d = {}
    for idx,col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def main(argv, environ):
    global vflag
    nodb_flag = false
    freq_flag = false
    db_path = DEFAULT_DATABASE
    sql_file = ""
    argc = len(argv)

    if argc == 1:
        usage(argv[0])
        sys.exit(0)
 
    try:
        alist, args = getopt.getopt(argv[1:], "hvd:c:f:nV",
                ["help", "verbose", "database=", "create=", "frequency=",
                 "nodb", "version"])
    except getopt.GetoptError, msg:
        print "%s: %s\n" % (argv[0], msg)
        usage(argv[0]);
        sys.exit(1)
 
    for(field, val) in alist:
        if field in ("-h", "--help"):
            usage(argv[0])
            sys.exit(0)
        if field in ("-v", "--verbose"):
            vflag = true
        if field in ("-d", "--database"):
            db_path = val
        if field in ("-c", "--create"):
            sql_file = val
        if field in ("-f", "--frequency"):
            freq_flag = true
            db_path = val
        if field in ("-n", "--nodb"):
            nodb_flag = true
        if field in ("-V", "--version"):
            print "nmapdb v%s by Patroklos Argyroudis <argp at domain census-labs.com>" % (VERSION)
            print "parse nmap's XML output files and insert them into an SQLite database"
            sys.exit(0)

    if freq_flag == false:
        if len(args[0]) == 0:
            usage(argv[0])
            sys.exit(1)

    if nodb_flag == false:
        if db_path == DEFAULT_DATABASE:
            print "%s: no output SQLite DB file specified, using \"%s\"\n" % (argv[0], db_path)

        conn = sqlite.connect(db_path)
        cursor = conn.cursor()

        myprint("%s: successfully connected to SQLite DB \"%s\"\n" % (argv[0], db_path))

        # helpful queries on the database
        if freq_flag == true:
            freq_sql = "select count(port) as frequency,port as fport from ports where ports.state='open' group by port having count(fport) > 1000"

            cursor.execute(freq_sql)
            print "Frequency|Port"

            for row in cursor:
                print(row)
            
            sys.exit(0)

    if nodb_flag == false:
        if sql_file != "":
            sql_string = open(sql_file, "r").read()
        
            try:
                cursor.executescript(sql_string)
            except sqlite.ProgrammingError, msg:
                print "%s: error: %s\n" % (argv[0], msg)
                sys.exit(1)

            myprint("%s: SQLite DB created using SQL file \"%s\"\n" % (argv[0], sql_file))
    
    for fname in args:
        try:
            doc = xml.dom.minidom.parse(fname)
        except IOError:
            print "%s: error: file \"%s\" doesn't exist\n" % (argv[0], fname)
            continue
        except xml.parsers.expat.ExpatError:
            print "%s: error: file \"%s\" doesn't seem to be XML\n" % (argv[0], fname)
            continue

        for host in doc.getElementsByTagName("host"):
            try:
                address = host.getElementsByTagName("address")[0]
                ip = address.getAttribute("addr")
                protocol = address.getAttribute("addrtype")
            except:
                # move to the next host since the IP is our primary key
                continue

            try:
                mac_address = host.getElementsByTagName("address")[1]
                mac = mac_address.getAttribute("addr")
                mac_vendor = mac_address.getAttribute("vendor")
            except:
                mac = ""
                mac_vendor = ""

            try:
                hname = host.getElementsByTagName("hostname")[0]
                hostname = hname.getAttribute("name")
            except:
                hostname = ""

            try:
                status = host.getElementsByTagName("status")[0]
                state = status.getAttribute("state")
            except:
                state = ""

            try:
                os_el = host.getElementsByTagName("os")[0]
                os_match = os_el.getElementsByTagName("osmatch")[0]
                os_name = os_match.getAttribute("name")
                os_accuracy = os_match.getAttribute("accuracy")
                os_class = os_el.getElementsByTagName("osclass")[0]
                os_family = os_class.getAttribute("osfamily")
                os_gen = os_class.getAttribute("osgen")
            except:
                os_name = ""
                os_accuracy = ""
                os_family = ""
                os_gen = ""

            try:
                timestamp = host.getAttribute("endtime")
            except:
                timestamp = ""

            try:
                hostscript = host.getElementsByTagName("hostscript")[0]
                script = hostscript.getElementsByTagName("script")[0]
                id = script.getAttribute("id")

                if id == "whois":
                    whois_str = script.getAttribute("output")

                else:
                    whois_str = ""
                # nmap smb plugin support
                if id == "smb-protocols":
                    smb_protocols = script.getAttribute("output")
                else:
                    smb_protocols = ""




            except:
                whois_str = ""
                smb_protocols = ""

            myprint("================================================================")

            myprint("[hosts] ip:\t\t%s" % (ip))
            myprint("[hosts] mac:\t\t%s" % (mac))
            myprint("[hosts] hostname:\t%s" % (hostname))
            myprint("[hosts] protocol:\t%s" % (protocol))
            myprint("[hosts] os_name:\t%s" % (os_name))
            myprint("[hosts] os_family:\t%s" % (os_family))
            myprint("[hosts] os_accuracy:\t%s" % (os_accuracy))
            myprint("[hosts] os_gen:\t\t%s" % (os_gen))
            myprint("[hosts] last_update:\t%s" % (timestamp))
            myprint("[hosts] state:\t\t%s" % (state))
            myprint("[hosts] mac_vendor:\t%s" % (mac_vendor))
            myprint("[hosts] whois:\n")
            myprint("[hosts] smb_protocols:\t%s" % (smb_protocols))
            myprint("%s\n" % (whois_str))

            if nodb_flag == false:
                try:
                    cursor.execute("INSERT INTO hosts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (ip, mac, hostname, protocol, os_name, os_family, os_accuracy,
                            os_gen, timestamp, state, mac_vendor, whois_str))
                except sqlite.IntegrityError, msg:
                    #print "%s: warning: %s: table hosts: ip: %s\n" % (argv[0], msg, ip)
                    #continue
                    cursor.execute("SELECT * FROM hosts WHERE ip = '%s'" % ip )
                    db = dict_factory(cursor, cursor.fetchone())
                    if not (  db['mac']        == mac
                          and db['hostname']   == hostname
                          and db['protocol']   == protocol
                          and db['os_name']    == os_name
                          and db['os_family']  == os_family
                          and db['os_gen']     == os_gen
                          and db['state']      == state
                          and db['mac_vendor'] == mac_vendor
                          and db['whois']      == whois_str):
                        # So we already have an entry. If theres no new information we continue to ports
                        # If there's a bunch of new entries we'll ask the user what to do
                        print "[hosts] Name:        'Old' --> 'New'"
                        print("[hosts] mac:         '"+db['mac']+"' --> '%s'" % mac)
                        print("[hosts] hostname:    '"+db['hostname']+"' --> '%s'" % hostname)
                        print("[hosts] protocol:    '"+db['protocol']+"' --> '%s'" % protocol)
                        print("[hosts] os_name:     '"+db['os_name']+"' --> '%s'" % os_name)
                        print("[hosts] os_family:   '"+db['os_family']+"' --> '%s'" % os_family)
                        print("[hosts] os_accuracy: '"+str(db['os_accuracy'])+"' --> '%s'" % os_accuracy)
                        print("[hosts] os_gen:      '"+db['os_gen']+"' --> '%s'" % os_gen)
                        print("[hosts] timestamp:   '"+str(db['last_update'])+"' --> '%s'" % timestamp)
                        print("[hosts] state:       '"+db['state']+"' --> '%s'" % state)
                        print("[hosts] mac_vendor:  '"+db['mac_vendor']+" --> '%s'" % mac_vendor)
                        print("[hosts] whois:       '"+db['whois']+"' --> '%s'" % whois_str)                        
                        print "=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
                        print "[hosts] Update entry? y/n"
                        user_input = sys.stdin.readline().strip()[:1]
                        if user_input == 'y':
                            myprint("[hosts] updating %s entry" % ip)
                            sql = ("UPDATE hosts SET mac='%s', hostname='%s', protocol='%s', os_name='%s', os_family='%s', os_accuracy='%s', os_gen='%s', last_update='%s', state='%s', mac_vendor='%s', whois='%s' WHERE ip = '%s'" %
                  (mac,hostname,protocol,os_name,os_family,os_accuracy,os_gen,timestamp,state,mac_vendor,whois_str, ip ))
                            cursor.execute(sql)

                        else:
                            myprint("[hosts] Skipping %s entry" % ip)
                            continue




                except:
                    print "%s: unknown exception during insert into table hosts\n" % (argv[0])
                    continue

            try:
                ports = host.getElementsByTagName("ports")[0]
                ports = ports.getElementsByTagName("port")
            except:
                print "%s: host %s has no open ports\n" % (argv[0], ip)
                continue

            for port in ports:
                pn = port.getAttribute("portid")
                protocol = port.getAttribute("protocol")
                state_el = port.getElementsByTagName("state")[0]
                state = state_el.getAttribute("state")

                try:
                    service = port.getElementsByTagName("service")[0]
                    port_name = service.getAttribute("name")
                    product_descr = service.getAttribute("product")
                    product_ver = service.getAttribute("version")
                    product_extra = service.getAttribute("extrainfo")
                except:
                    service = ""
                    port_name = ""
                    product_descr = ""
                    product_ver = ""
                    product_extra = ""
                    
                service_str = "%s %s %s" % (product_descr, product_ver, product_extra)

                info_str = ""

                for i in (0, 1):
                    try:
                        script = port.getElementsByTagName("script")[i]
                        script_id = script.getAttribute("id")
                        script_output = script.getAttribute("output")
                    except:
                        script_id = ""
                        script_output = ""

                    if script_id != "" and script_output != "":
                        info_str += "%s: %s\n" % (script_id, script_output)

                myprint("\t------------------------------------------------")

                myprint("\t[ports] ip:\t\t%s" % (ip))
                myprint("\t[ports] port:\t\t%s" % (pn))
                myprint("\t[ports] protocol:\t%s" % (protocol))
                myprint("\t[ports] name:\t\t%s" % (port_name))
                myprint("\t[ports] state:\t\t%s" % (state))
                myprint("\t[ports] service:\t%s" % (service_str))
                
                if info_str != "":
                    myprint("\t[ports] info:\n")
                    myprint("%s\n" % (info_str))


                # nmap smb plugin support
                if smb_protocols:
                    try:
                        hostscript = host.getElementsByTagName("hostscript")[0]
                        script = hostscript.getElementsByTagName("script")[0]
                        table = script.getElementsByTagName("table")[0]
                        elems = table.getElementsByTagName("elem")
                        myprint("%s" % hostscript.firstChild.nodeValue)
                    except:
                        print "%s: host %s has no hostscript\n" % (argv[0], ip) 
                        continue

                    smb1="disabled"
                    smb2="disabled"
                    smb3="disabled"
                    for elem in elems:
                        smb_version = elem.firstChild.nodeValue
                        myprint("Debug smb_version : %s" % smb_version)
                        if "SMBv1" in smb_version:
                            smb1="enabled"
                        if "2." in smb_version:
                            smb2="enabled"
                        if "3." in smb_version:
                            smb3="enabled"

                    myprint("Debug smb1 : %s" % smb1)
                    myprint("Debug smb2 : %s" % smb2)
                    myprint("Debug smb3 : %s" % smb3)
               # / nmap smb plugin support 


                if nodb_flag == false:
                    try:
                        cursor.execute("INSERT INTO ports VALUES (?, ?, ?, ?, ?, ?, ?)", (ip, pn, protocol, port_name, state, service_str, info_str))
                    except sqlite.IntegrityError, msg: # Si on a une erreur de contrainte d'intgrit
                        #print "%s: warning: %s: table ports: ip: %s\n" % (argv[0], msg, ip)
                        #continue
                        # Support des updates
                        #cursor.execute("SELECT * FROM ports WHERE ip = '%s' AND port = '%s' and protocol ='%s'" % (ip, pn, protocol) )
                        #db = dict_factory(cursor, cursor.fetchone())

                        #if info_str != "" and db['info'].find(info_str) <= 0:
                            #new_info = db['info'] + "\n" + info_str
                            #myprint("[ports] Appending info %s" % info_str)
                            #cursor.execute("UPDATE ports SET info=? WHERE ip = ? AND port = ? and protocol =?" , (new_info, ip, pn, protocol))


                        #if db['name'] != port_name or db['service'] != service_str or db['state'] != state:
                            #print '[ports] %s:%s %s exists' % (ip, pn, protocol)
                            #print "=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
                            #print "[ports] Name:     'Old' --> 'New'"
                            #print("[ports] ip:       '"+db['ip']+"' --> '%s'" % ip)
                            #print("[ports] port:     '"+str(db['port'])+"' --> '%s'" % pn)
                            #print("[ports] protocol: '"+db['protocol']+"' --> '%s'" % protocol)
                            #print("[ports] name:     '"+db['name']+"' --> '%s'" % port_name)
                            #print("[ports] state:    '"+db['state']+"' --> '%s'" % state)
                            #print("[ports] service:  '"+db['service']+"' --> '%s'" % service_str)
                            #print "=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
                            #print "[ports] Update entry? y/n"
                            #user_input = sys.stdin.readline().strip()[:1]
                        cursor.execute("UPDATE ports SET name=?, state=?, service=? WHERE ip = ? AND port = ? and protocol = ?",
                               (port_name, state, service_str, ip, pn, protocol))
                    except:
                        print "%s: unknown exception during insert into table ports\n" % (argv[0])
                        continue

                myprint("\t------------------------------------------------")

                # nmap smb plugin support
                if smb_protocols:
                    if nodb_flag == false:
                        try:
                            cursor.execute("INSERT INTO smb VALUES (?, ?, ?, ?, ?, ?)", (ip, pn, protocol, smb1, smb2, smb3))
                        except sqlite.IntegrityError, msg:
                            #print "%s: warning: %s: table smb: ip: %s\n" % (argv[0], msg, ip)
                            #continue
                            #cursor.execute("SELECT * FROM smb WHERE ip = '%s' AND port = '%s' and protocol ='%s'" % (ip, pn, protocol) )
                            #db = dict_factory(cursor, cursor.fetchone())

                        #if info_str != "" and db['info'].find(info_str) <= 0:
                            #new_info = db['info'] + "\n" + info_str
                            #myprint("[ports] Appending info %s" % info_str)
                            #cursor.execute("UPDATE smb SET smb1=?, smb2=?, smb3=? WHERE ip = ? AND port = ? and protocol =?" , (smb1, smb2, smb3, ip, pn, protocol))


                            #if db['name'] != port_name or db['service'] != service_str or db['state'] != state:
                             #print '[ports] %s:%s %s exists' % (ip, pn, protocol)
                             #print "=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
                             #print "[ports] Name:     'Old' --> 'New'"
                             #print("[ports] ip:       '"+db['ip']+"' --> '%s'" % ip)
                             #print("[ports] port:     '"+str(db['port'])+"' --> '%s'" % pn)
                             #print("[ports] protocol: '"+db['protocol']+"' --> '%s'" % protocol)
                             #print("[ports] name:     '"+db['name']+"' --> '%s'" % port_name)
                             #print("[ports] state:    '"+db['state']+"' --> '%s'" % state)
                             #print("[ports] service:  '"+db['service']+"' --> '%s'" % service_str)
                             #print "=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
                            #print "[smb] Update entry? y/n"
                            #user_input = sys.stdin.readline().strip()[:1]
                            cursor.execute("UPDATE smb SET smb1=?, smb2=?, smb3=? WHERE ip = ? AND port = ? and protocol = ?",
                                       (smb1, smb2, smb3, ip, pn, protocol))
                        except:
                            print "%s: unknown exception during insert into table smb\n" % (argv[0])
                            print "ip : %s" % (ip)
                            print "pn : %s" % pn
                            print "protocol : %s" % protocol
                            print "smb1 : %s" % smb1
                            print "smb2 : %s" % smb2
                            print "smb3 : %s" % smb3
                            continue

                    myprint("\t------------------------------------------------")


            myprint("================================================================")

    if nodb_flag == false:
        conn.commit()

if __name__ == "__main__":
    main(sys.argv, os.environ)
    sys.exit(0)

# EOF
