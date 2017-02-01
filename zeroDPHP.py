#!/usr/bin/env python
# drd0s aka JustPassingBy 

import argparse, os, sys, re, requests, subprocess, datetime
from os import listdir
from os.path import isdir, join
from bs4 import BeautifulSoup as bs

def pinfo(info):
  print "\033[92m[I] " + info + "\033[0m"

def analyse_code( codedir ):
 global args
 print "[.] Analysing code in " + codedir 

 if args.binaries:
  binmode = 'a'
 else:
  binmode = 'I'

 uservar = '\$_\(GET\|POST\|COOKIE\|REQUEST\|SERVER\|FILES\|ENV\)\['
 uservarany = uservar + '[\'\\"][^\'\\"]\+[\'\\"]\]'

 # RCE
 code_search( 'grep -irHn'+binmode+' "[^\._a-z]\(assert\|create_function\|assert\|eval\|passthru\|system\|exec\|shell_exec\|pcntl_exec\|popen\|proc_open\)([^\$]*\$[^\$]*)" '+codedir+' | grep -v "\.\(js\|css\|js\.php\):"', "RCE" ) # RCE Functions
 code_search( 'grep -rHn'+binmode+' "\`[^\$]*\$[^\$]\+\`;\s*$" '+codedir+'| grep -v "\.\(js\|css\|js\.php\):"', "RCE" ) # Shell exec via backticks
 code_search( 'grep -irHn'+binmode+' "[^\._a-z]preg_[a-z](\s*[\'\\"]/.*/[a-z]*e[a-z]*[\'\\"]" '+codedir+'| grep -v "\.\(js\|css\|js\.php\):"', "RCE" ) # Code exec via preg functions with /e
 code_search( 'grep -irHn'+binmode+' "[^\._a-z]preg_[a-z]([^,]*\$" '+codedir+'| grep -v "\.\(js\|css\|js\.php\):"', "RCE" ) # Code exec via preg functions passing entire pattern
 
 # SQLI
 code_search( 'grep -irHn'+binmode+' "\$\(stmt\|sqltext\|sql_string\|sqlauthority\|save_query\|querystring\|squerystring2\|squerystring\|where_str\|sdelete\|sinsert\|ssubquery\|selectwhere\|swhere\|supdate\|countsql\|squery\|sselect\|sq\|sql\|qry\|query\|where\|select\|order\|limit\)\W" '+codedir+' | grep "'+uservar+'"', "SQLI" )
 code_search( 'grep -irHn'+binmode+' "\w->\(sql\)\W" '+codedir+' | grep "\. *'+uservar+'"', "SQLI" )
 code_search( 'grep -irHn'+binmode+' "\(mysql_query\|mssql_query\|pg_query\|mysqli_query\|db_query\)" ' + codedir+' | grep "'+uservar+'"', "SQLI" )
 code_search( 'grep -irHn'+binmode+' "db->\(get_row\|get_results\|query\|get_var\)" ' + codedir+' | grep "'+uservar+'"', "SQLI" )

 # High severity issues
 if args.severity >= 2:
 
   # Object injection
   code_search( 'grep -rHn'+binmode+' "'+uservar+'" '+codedir+' | grep "unserialize("', "OBJI" )
   
   # File upload handling
   code_search( 'grep -rHn'+binmode+' "\$_FILES\[[\\"\'][^\\"\']\+[\\"\']\]\[[\\"\']name[\\"\']\]" ' + codedir, "FILE" )
   
   # SSRF
   code_search( 'grep -rHn'+binmode+' "\(curl_exec\|ftp_connect\|ftp_ssl_connect\|pfsockopen\|socket_bind\|socket_connect\|socket_listen\|socket_create_listen\|socket_accept\|socket_getpeername\|socket_send\|curl_init\|fsockopen\|stream_context_create\|get_headers\)(" '+codedir+' | grep "'+uservar+'"', "SSRF" )
   code_search( 'grep -rHn'+binmode+' "CURLOPT_URL" '+codedir+' | grep "'+uservar+'"', "SSRF" )
   
   # Local file inclusion
   code_search( 'grep -rHn'+binmode+' "\$\w\+" '+codedir+' | grep "\(file_get_contents\|fopen\|SplFileObject\|include\|require\|include_once\|require_once\|show_source\|highlight_file\)("', "LFI" )
   
   # XSS
   code_search( 'grep -rHn'+binmode+' "'+uservar+'" '+codedir+' | grep "\(<\w\|\w>\)"', "XSS" )
   code_search( 'grep -rHn'+binmode+' "^\s*\(echo\|print\)" '+codedir+' | grep "'+uservar+'"', "XSS" )
 
   # CRLF Injection
   code_search( 'grep -irHn'+binmode+' "\Wheader(" '+codedir+' | grep "'+uservar+'"', "CRLF" )

 # Medium severity issues
 if args.severity >= 3:
 
   # Code control
   code_search( 'grep -rHn'+binmode+' "[^\._a-z]\(call_user_func\|call_user_func_array\)([^\$]*\$[^\$]*)" '+codedir+' | grep -v "\.\(js\|css\|js\.php\):"', "CTRL" )
   code_search( 'grep -rHn'+binmode+' "\$\w\+(" '+codedir+' | grep -v "\.\(js\|css\|js\.php\):"', "CTRL" )
   code_search( 'grep -irHn'+binmode+' "function \+__\(destruct\|wakeup\|tostring\)(" '+codedir+' | grep -v "\.\(js\|css\|js\.php\):"', "CTRL" )
   code_search( 'grep -rHn'+binmode+' "'+uservar+'[\'\\"]\(test\|debug\)" '+codedir, "DBUG" )
   code_search( 'grep -irHn'+binmode+' "parse_str( *'+uservarany+' *)" ' + codedir, "VARS" )
   code_search( 'grep -rHn'+binmode+' "md5(" '+codedir, "CRYP" )
   code_search( 'grep -rHn'+binmode+' "CRYPT_MD5" '+codedir, "CRYP" )
   code_search( 'grep -rHn'+binmode+' "CRYPT_EXT_DES" '+codedir, "CRYP" )
   code_search( 'grep -rHn'+binmode+' "CRYPT_STD_DES" '+codedir, "CRYP" )


 if args.severity == 4:
   
   # phpinfo()
   code_search( 'grep -rHn'+binmode+' "phpinfo(" '+codedir, "INFO" )

   # Todo items
   code_search( 'grep -rHni'+binmode+' "\W\(TODO\|FIXME\|HACK\)\W" '+codedir+' | grep "\.php:"', "TODO", True )

# Search using a given grep command, parse and log the response
def code_search( cmd, genre="", allowcomments=False ):
  global args

  # remove single line comments
  if not allowcomments:
    cmd = cmd + ' | grep -v "\.php:[0-9]\+: *\/\/"'

  if args.debug:
    print "[D] " + cmd
  out = ''
  try:
    out = subprocess.check_output( cmd + " | sed 's/^/[!]["+genre+"] /'", shell=True )
  except subprocess.CalledProcessError as e:
    pass
  if out.strip() != '': 
    if not args.nologfile:
      f = open( args.logfile, "a" )
      f.write( out )
      f.close()
    out = re.sub( "(\[!\]\[[A-Z]+\])(.+[0-9]+:)(.*)$", "\033[91m\g<1>\033[0m\g<2>\033[93m\g<3>\033[0m", out, 0, re.M )
    print out
  return out
  
#
# Start
#

# Command line options
parser = argparse.ArgumentParser(description="Grab the most dumb flaws in php.")
parser.add_argument("-L", "--nologfile", action="store_true", help="Disable writing a log file")
parser.add_argument("-n", "--nodownload", action="store_true", help="Don't do any scraping, just analyse any code already present")
parser.add_argument("-a", "--analyse", help="Just analyse a folder without doing anything else")
parser.add_argument("-b", "--binaries", action="store_true", help="Search within binary files as if they were text")
parser.add_argument("-s", "--severity", choices=['1','2','3','4'], help="Report only issues of this severity level and up (1=critical, 4=medium)")
parser.add_argument("--debug", help="Output search commands")
if len( sys.argv)==1:
  parser.print_help()
  sys.exit(1)
args = parser.parse_args()



if args.nologfile:
  pinfo( "Not writing a log file" )
else:
  pinfo( "Logging to " + args.logfile )

logdir = os.path.dirname(args.logfile)
if not os.path.exists( logdir ):
  os.makedirs( logdir )

if not args.severity:
  args.severity = 4

args.severity = int(args.severity)

if args.analyse:
  analyse_code(args.analyse)
elif args.nodownload:
  analyse_all_plugins(args.outputdir)
elif args.wpscan:
  parse_wpscan_output( args.wpscan )
elif args.plugins:
  scrape_plugindir( args.plugindir )
else:
  print "Nothing to do!"
  parser.print_help()

