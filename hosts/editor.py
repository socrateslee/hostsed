'''
Utilities for adding or deleting entries on hosts file
as /etc/hosts.
'''
import os
import sys
import json
import subprocess
import socket
import argparse


def is_valid_ip_address(ip):
    '''
    Check whether an ip address is valid, both for ipv4
    and ipv6.
    '''
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        pass

    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        pass
    return False


def parse_line(line):
    pos = line.find("#")
    new_line = line[:pos].strip() if pos != -1 else line.strip()
    comment = line[pos:] if pos != -1 else ''
    if new_line:
        parts = list(map(lambda x: x.strip(), new_line.split()))
        return (line, parts, comment)
    else:
        return (line, None, comment)
        

class HostEditor(object):
    def __init__(self, filename='/etc/hosts'):
        self.filename = filename
        self._parse()

    def add(self, ip, *hostnames):
        '''
        Add an entry to hosts file.
        '''
        if not self.entries:
            return
        ret = []
        added = False
        if not self.entries:
            return
        for (line, parts, comment) in self.entries:
            if parts and parts[0] == ip and not added:
                for hostname in hostnames:
                    if hostname not in parts[1:]:
                        parts.append(hostname)
                line = ' '.join(['\t'.join(parts), comment])
                added = True
            ret.append((line, parts, comment))
        if not added:
            parts = [ip] + list(hostnames)
            line = '\t'.join(parts)
            ret.append((line, parts, comment))
        self.entries = ret

    def delete(self, ip, hostname):
        '''
        Delete an entry from hosts file.
        '''
        if not is_valid_ip_address(ip):
            raise Exception("Ip %s is not valid." % ip)
        ret = []
        for (line, parts, comment) in self.entries:
            if parts and parts[0] == ip:
                parts = list(filter(lambda x: x != hostname, parts))
                if not parts[1:]:
                    continue
                line = ' '.join(['\t'.join(parts), comment])
            ret.append((line, parts, comment))
        self.entries = ret

    def _parse(self):
        '''
        Parse the files into entries.
        '''
        self.entries = []
        for line in open(self.filename).readlines():
            self.entries.append(parse_line(line))

    def output(self, fd=None):
        if fd is None:
            fd = sys.stdout
        fd.write('\n'.join(map(lambda x: x[0].strip(), self.entries)))

    def write(self):
        fd = open(self.filename, 'w')
        self.output(fd=fd)
        fd.close()

    def output_docker_ip(self, container):
        proc = subprocess.Popen("docker inspect %s" % container,
                                shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        if proc.returncode == 0:
            ret = json.loads(stdout.decode('utf-8'))
            ip = ret[0]['NetworkSettings']['IPAddress']
            sys.stdout.write(ip)


def main():
    he = HostEditor()
    if len(sys.argv) >= 4 and sys.argv[1] == 'add':
        he.add(sys.argv[2], *sys.argv[3:])
        he.write()
        he.output()
    elif len(sys.argv) == 4 and sys.argv[1] in ('rm', 'remove',
                                                'del', 'delete'):
        he.delete(sys.argv[2], sys.argv[3])
        he.write()
        he.output()
    elif len(sys.argv) == 3 and sys.argv[1] == 'docker':
        he.output_docker_ip(sys.argv[2])
    else:
        he.output()


if __name__ == '__main__':
    main()
