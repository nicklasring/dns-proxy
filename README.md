- Capture dns query in wireshark
- Understand processflow

- Make a dns query to the proxy
- Translate the query
- Pass the message along to primary DNS
- Handle response from primary dns
- Send back to client


--------
Features
--------

1. Be able to disallow domains from a blacklist file
2. Be able to spoof certain domains and redirect to fake site
    - Have a webserver running listening on these domains, serving fake pages, atleast one forbidden page if no "troll-pages"
    - Be able to interactively create & spoof domains
        > if dst.ip == 1.1.1.1: serveDomain('myDomain2')

