$XMLInputPath = "<Path to the output XML created by the sniffer>"
$HashcatHashOutputPath = "<Path where you want the Hashcat formatted hashes dumped>"

$Results = foreach($ResultObject in @(([xml](Get-Content $XMLInputPath)).ResultObjects.ResultObject.GetEnumerator())) {
  "{0}::{1}:{2}:{3}" -F $ResultObject.UserName.ToUpper(), $ResultObject.ClientDomainName.ToUpper(), $ResultObject.ServerChallenge.ToLower(), $ResultObject.NtChallengeString.ToLower()
}
$Results | Out-File -FilePath $HashcatHashOutputPath -Encoding ascii
