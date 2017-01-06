HSTS Preload Readiness Checker
==============================
Prior to submitting a domain to the [HSTS preload list](https://hstspreload.org/) you'll want to make sure that all of the subdomains of a given domain are all available on HTTPS.

This script helps you do that. It takes a BIND master file as input, attempts to connect to each host on both HTTP and HTTPS and then outputs the results in an easy to action format (or CSV if you prefer).

How to run
----------
You'll need to have a 1.8 JVM and [Ammonite](http://www.lihaoyi.com/Ammonite/) (better than `0.8.1` recommended) installed to run this script. If you are on OSX then simply `brew install ammonite-repl` should do the job.

Once installed you can run the script using `./HstsAnalyser.sc <file> [output]`. The file should be a BIND format zone file and output can be one of `csv` or `terminal` and defaults to `terminal`.

Some examples:
 
 - `./HstsAnalyser.sc example.net.zonefile csv` = write out a CSV report for the zone
 - `./HstsAnalyser.sc example.net.zonefile -- --verbose true` = write out a verbose report that includes results that are successful on HTTPS with a suitable HSTS header and also results where no connection could be made on HTTP or HTTPS

Caveats
-------
This only checks services that are found on standard HTTP and HTTPS ports. Hosts that provide HTTP services on non-standard ports will not be discovered. 

To-do
-----
 - Provide option to analyse a Route53 zone
 - Parse non-standard CNAME records found in Dyn BIND files