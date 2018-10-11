HSTS Preload Readiness Checker
==============================
Prior to submitting a domain to the [HSTS preload list](https://hstspreload.org/) you'll want to make sure that all of the subdomains of a given domain are all available on HTTPS.

This project helps you do that. It takes either a BIND master file as input or fetches a zone from Route53. It then attempts to connect to each host on both HTTP and HTTPS and then outputs the results in an easy to action format (or CSV if you prefer).

How to run
----------
You'll need to have a 1.8 JVM and [SBT](https://www.scala-sbt.org/). If you are on OSX then simply `brew install sbt` should do the job.

Once installed you can run the SBT build tool using `sbt` in the root of the repository. Once you have an `sbt` prompt you can run it using `run`. Usage information will be displayed with no arguments. 

Some examples:
 
 - `run -b example.net.zonefile -o csv` = write out a CSV report for the zone stored in the specified BIND file 
 - `run -z example.net -r eu-west-1 -v` = write out a verbose report for a zone in Route53 that includes results that are successful on HTTPS with a suitable HSTS header and also results where no connection could be made on HTTP or HTTPS

Caveats
-------
This only checks services that are found on standard HTTP and HTTPS ports. Hosts that provide HTTP services on non-standard ports will not be discovered. 
