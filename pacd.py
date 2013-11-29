import signal
import logging
import os
import sys
import subprocess

import gevent
import gevent.wsgi


BACKEND_IP, BACKEND_PORT = sys.argv[1], sys.argv[2]

LOGGER = logging.getLogger(__name__)
with open('whitelist.pac') as f:
    WHITELIST_PAC = f.read() % BACKEND_IP
visitors = set()


def handle_pac(environ, start_response):
    if '/pac' != environ['PATH_INFO']:
        start_response('404 NOT FOUND', [('Content-Type', 'text/plain')])
        return []
    start_response('200 OK', [('Content-Type', 'text/javascript')])
    remote_addr = environ['REMOTE_ADDR']
    if remote_addr in visitors:
        return [WHITELIST_PAC]
    visitors.add(remote_addr)
    subprocess.call(
        'iptables -t nat -I PREROUTING -s %s -p tcp -d %s --dport 25 -j DNAT --to-destination 10.1.2.3:%s' % (
            remote_addr, BACKEND_IP, BACKEND_PORT), shell=True)
    subprocess.call(
        'iptables -I OUTPUT -d %s -j ACCEPT' % remote_addr, shell=True)
    return [WHITELIST_PAC]


def main():
    logging.basicConfig(level=logging.DEBUG)
    signal.signal(signal.SIGINT, lambda signum, fame: os._exit(0))
    try:
        server = gevent.wsgi.WSGIServer(('', 80), handle_pac)
        LOGGER.info('serving PAC on port 80...')
    except:
        LOGGER.exception('failed to start')
        os._exit(1)
    server.serve_forever()


if '__main__' == __name__:
    main()