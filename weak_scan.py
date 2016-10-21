#!/usr/bin/env python
#coding=utf-8

import os
import nmap
import optparse

def NmapScan(tgthost,fast):
	dict={}
	nmscan=nmap.PortScanner()
	if fast:
		results=nmscan.scan(tgthost,'21,143,1433,3306,119,5631,110,5432,445,25,22,3690,23,5900')
	else:
		results=nmscan.scan(tgthost)
	hosts=nmscan.all_hosts()#返回所有存活主机列表
	if len(hosts)==0:
		print "No active host."
		exit()
	for host in hosts:
		services=[]
		
		#过滤掉所有没开任何端口的主机
		if not nmscan[host].has_key('tcp'):
			continue
		ports=nmscan[host]['tcp'].keys()
		for port in ports:
			#status=results['scan'][host]['status']['state']
			state=results['scan'][host]['tcp'][int(port)]['state']
			if state=='open':
				service=results['scan'][host]['tcp'][int(port)]['name']
				services.append(service)
		if len(services)!=0:
			dict[host]=services
			
	if len(dict.keys())==0:
		print "No active port."
		exit()
	return dict
	
def Medusa(dict,USERFILE,PASSFILE):
	modules=['ftp','imap','mssql','mysql','nntp','pcanywhere','pop3','postgres','smbnt','smtp','ssh','svn','vmauthd','telnet','vnc']
	hosts=dict.keys()
	for host in hosts:
		services=dict[host]
		for service in services:
			if service=='unknown':
				continue
			if service in modules:
				os.system('medusa -h %s -U %s -P %s -M %s -e n -O %s' % (host,USERFILE,PASSFILE,service,'out.log'))		

def main():
	banner='''
                    _                        
__      _____  __ _| | _____  ___ __ _ _ __  
\ \ /\ / / _ \/ _` | |/ / __|/ __/ _` | '_ \ 
 \ V  V /  __/ (_| |   <\__ \ (_| (_| | | | |
  \_/\_/ \___|\__,_|_|\_\___/\___\__,_|_| |_|
  
Date:2016-10-09 Author:zjf Support Services:

'ftp','imap','mssql','mysql','nntp','pcanywhere','pop3','postgres','smbnt','smtp','ssh','svn','vmauthd','telnet','vnc'
'''
	parser=optparse.OptionParser('%prog -U <USERFILE> -P <PASSFILE> [-F <True|False>] <ip|netblock>')
	parser.add_option('-U',dest='USERFILE',type='string',help='specify a file of usernames')
	parser.add_option('-P',dest='PASSFILE',type='string',help='specify a file of passwords')
	parser.add_option('-F',dest='FAST',default=False,help='specify fast mode')
	options,args=parser.parse_args()
	USERFILE=options.USERFILE
	PASSFILE=options.PASSFILE
	FAST=options.FAST
	if USERFILE is None or PASSFILE is None:
		print banner
		parser.print_help()
		exit()
	if len(args)!=1:
		print banner
		parser.print_help()
		exit()
	if os.path.exists('out.log'):
		os.remove('out.log')
	print banner
	print "Scanner is running ..."
	tgthost=args[0]
	dict=NmapScan(tgthost,FAST)
	Medusa(dict,USERFILE,PASSFILE)
	with open('out.log','r') as f:
		lines=f.readlines()
	saveLines=[]
	for line in lines:
		if line[0]!='#':
			saveLines.append(line)
	with open('out.log','w') as f:
		f.writelines(saveLines)
	print "Results have saved in out.log"
	
if __name__=='__main__':
	main()