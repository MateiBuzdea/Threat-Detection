# TASK 1
For this task, I implemented the euristics provided in the document and some
additional ones:
* The extension check, as mentioned in the document, but with two more
  extensions, `bin`, `sh` and `pl`
* The known malicious domain check , which checks if the domain is present in
  the blacklist database
* The euristic that checks if there are too many numbers in the hostname (if
  yes, this can be an IP or another evil host)
* If the hostname is known to be very popular, such as google, the url is not
  considered malicious
* If the host name is too long (more than 31 chars), it is probably malicious.
  because common domains are not very long
* If the hostname contains the `:` character, it means the connection is made to
  a specific port, so probably malicious; also, if `@` is present, the
  connection is made with credentials, so again may be malicious
* If path contains bad chars, such as `~`, flag it
* If the number of `com` sequence is bigger than one, it may be a trick to mask
  a bad hostname, so mark it as malicious
* If the path contains bad words such as `paypal`
* If the hostname is not the same as the words in the whitelist, but it is very
  alike, mark the host as malicious

The full algorithm just takes each url from the file, parses it through a
function that returns the extracted hostname and path and the analyses these
parameters for the signs of malware described above. Then it prints on the
output file the result of the prediction.

# TASK 2
Here I implemented the given euristics, if the time is greater than one second
and payload is not zero and two additional rules:
* If the destination IP is broadcast, it probably is not malware
* If the average payload is size `40.0`, this is a sign of cryptominer, so flag
  it

Additionally, for each packet that is found to be malicious, its hostname is
saved inside a database of malicious ips in order to flag if it appears again.

The algorithm is the same with the one at task 1. It takes each packet, gets its
components (destination ip, source ip, time in seconds) and checks for signs of
malware. If the result is positive, mark it as malicious and write to output
file.
