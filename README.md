# CSE534
MITM attacks with ARP spoofing

requirements: [Scapy3](https://github.com/phaethon/scapy)


Instructions to run:

To properly DNS spoof someone you need to be hosting the fake webpage that will capture their information. To do this have a terminal open to the /fake_webpage directory, then run the command `sudo python -m SimpleHTTPServer 80` to run it on your localhost. Now when a user tries to connect to a webpage in their browser they will be greeted with yours!

This attack works over HTTP, for example try using businessinsider.com as a baseline and then compare to facebook.com. Connecting to BI.com will be redirected to the fake page while the HTTPS secured facebook.com will not.