#!/usr/bin/env python

import SimpleHTTPServer
import SocketServer
import sys

from requests import get

PORT = 8000

if __name__ == '__main__':
    old_stderr = sys.stderr
    with open('httpd.log', 'a') as f:
        sys.stderr = f

        
        Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
        try:
            httpd = SocketServer.TCPServer(("", PORT), Handler)

            httpd.serve_forever()
        except Exception:
            sys.stderr = old_stderr
            raise
