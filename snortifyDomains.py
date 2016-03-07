import os,sys

if sys.argv[1]:
  urlList = open(sys.argv[1]).readlines()
  urlList = map(lambda s: s.strip(), urlList)
else:
  print "Put the path and name of the URL file after the script"
  
crqName = sys.argv[1][sys.argv[1].rfind("\\")+1:sys.argv[1].rfind(".")]

#Snort rules require hex numbers in 1-byte blocks. Python doesn't always like to provide them that way
def zeropad(hexnum):
  if len(hexnum) % 2 == 1:
    return "0" + str(hexnum)[2:]
  return hexnum[2:]
  
def httpRules(urlList):
  hostSplit = [x[:x.index("/") if "/" in x else x for x in urlList]
  uriSplit = [x[x.index("/"):] if "/" in x else '' for x in urlList]
  hostContentRuleSection = ['content:"Host: ' + x + '"; http_header; ' for x in hostSplit]
  uriContentRuleSection = ['content:"' + x + '"; http_uri; ' if len(x) > 1 else "" for x in uriSplit]
  snortRule = []
  for rule in zip(hostContentRuleSection, uriContentRuleSection, urlList):
    if rule[1] == 0:
      snortRule.append('alert tcp $HOME_NET any -> any $HTTP_PORTS (msg:"' + crqName + ' HTTP request for ' + rule[2] + '";' + str(rule[0]) + ')\n')
    else:
      snortRule.append('alert tcp $HOME_NET any -> any $HTTP_PORTS (msg:"' + crqName + ' HTTP request for ' + rule[2] + '";' + str(rule[0]) + str(rule[1]) + ')\n')
  return snortRule
  
def dnsRules(urlList):
  hostList = [x[:x.index("/")] if "/" in x else x for x in urlList]
  eliminatePath = [x.split("/")[0] for x in urlList]
  urlSplit = [x.split(".") for x in eliminatePath]
  urlMash = [["|" + zeropad(hex(len(x))) + "|" + x for x in y] for y in urlSplit]
  urlDnsFormat = ["".join(x) for x in urlMash]
  urlFinal = zip(urlDnsFormat,hostList)
  snortRule = ['alert udp $HOME_NET any -> any 53 (msg:"' + crqName + ' dns request for ' + x[1] + '"; byte_test:1,!&,0xF8,2; content:"' + x[0] + '|00|";)\n' for x in urlFinal]
  return snortRule
  
rulesOut = open(crqName + " rules.txt","w")

for rule in dnsRules(urlList):
  rulesOut.write(rule)
  
for rule in httpRules(urlList):
  rulesOut.write(rule)
  
  rulesOut.close()
