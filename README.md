#bitproxy
A local proxy for Namecoin .bit domains.

phelix / Namecoin Project 2014, 2015

forked from PyMiProxy by Nadeem Douba / PyMiProxy Project 2012

License: GPL

##how to run
You need to have the Namecoin client running with the blockchain (almost) completely downloaded.
Also you need to have NMControl running.

1.) set your browser proxy to 127.0.0.1:8084
(or better set your browser proxy config via the included bitproxy.pac via file:// or file:///
This will only redirect .bit domains to the proxy.)

2.) install local root cert to be able to use https
    Firefox
        Tools->Options->Advanced->Certificates->View_Certificates->Authorities->
            Import...->ca.crt->"Trust this CA to identify websites"->OK->OK
           (it might then be necessary to wait a couple of seconds or even restart)
    Chrome/Internet Explorer/System (on Windows)
        Open ca.crt in file explorer->install_certificate...->local-machine->continue->
            yes->this storage->browse...->trusted root CA->ok->continue->finish->OK->OK

3.) Go to https://nf.bit and brag


##todo
    clean & refactor (modular with internetarchive/warcprox and certauth?)
    use sha256 d/ fingerprints
    instructions: how to add cert to firefox / system
    firefox plugin to add cert?
    firefox plugin to only proxy .bit/tls:.bit
    or use pac file for proxy config only for .bit/tls:.bit (served via bottle?)
    instructions: note about browser "certificate caching"
    test python 2.7.9 - should bail
    ! safes browsing history - can not simply be deleted without conflicting with browser cache
    improve caching (also for .bit?)
    pass on remote cert data in local cert
    occasional SSLEOFError: EOF occurred in violation of protocol (_ssl.c:590)  --> TLSv1 (SO)
    automatic certificate install for firefox via certutil or alternative?
    unclear error during client launch
    better error on domain not found
    better error messages on browser error page in general
