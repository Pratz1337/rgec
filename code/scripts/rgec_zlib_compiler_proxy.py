#!/usr/bin/python3
"""Native make's compiler endpoint; no cache keys or artifacts accepted here."""
import json
import socket
import sys

connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
connection.connect('/rgec-zlib-compiler.sock')
connection.sendall(json.dumps(sys.argv[1:]).encode())
connection.shutdown(socket.SHUT_WR)
parts = []
while True:
    part = connection.recv(65536)
    if not part: break
    parts.append(part)
connection.close()
reply = json.loads(b''.join(parts).decode())
sys.stdout.buffer.write(bytes.fromhex(reply['stdout']))
sys.stderr.buffer.write(bytes.fromhex(reply['stderr']))
sys.exit(reply['returncode'])
