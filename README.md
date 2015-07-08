Gator
=====

Gator is a small SOCKS4, SOCKS5 proxy

1. SOCKS4 just support connect command
1. SOCKS5 it does not implement the full RFC (1928) but it works for no-auth basic usage.

It was developed as an experiment in go, and with some love it could grow
into something useful, such as a HTTP filtering system (adblocking perhaps)
or if some kind of SSL auth were implemented, a privacy helper.

1. SOCK4 http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
1. SOCK5 http://www.rfc-editor.org/rfc/rfc1928.txt

License
-------
Affero General Public License

