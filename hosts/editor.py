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
        socket.inet_pton(socket.AF_INET6, ip)
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

    def chk_user_permissions(self):
        '''
        Check if current user has sufficient permissions to
        edit hosts file.
        Raise an exception if user is invalid
        '''
        if self.filename != '-' and not os.access(self.filename, os.W_OK):
            msg = 'User does not have sufficient permissions, are you super user?'
            raise Exception(msg)
        return

    def add(self, ip, *hostnames):
        '''
        Add an entry to hosts file.
        '''

        self.chk_user_permissions()
        if not is_valid_ip_address(ip):
            raise Exception("IP %s is not valid." % ip)

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
        self.write()
        self.output()

    def drop(self, ip_or_hostname):
        '''
        Drop lines with specified ip or hostname from hosts file.
        '''
        self.chk_user_permissions()
        ret = []
        for (line, parts, comment) in self.entries:
            if parts and ip_or_hostname in parts:
                continue
            ret.append((line, parts, comment))
        self.entries = ret
        self.write()
        self.output()

    def delete(self, ip, hostname):
        '''
        Delete host from the lines with (ip, hostname) tuple from hosts file.
        '''
        self.chk_user_permissions()
        if not is_valid_ip_address(ip):
            raise Exception("IP %s is not valid." % ip)
        ret = []
        for (line, parts, comment) in self.entries:
            if parts and parts[0] == ip:
                parts = list(filter(lambda x: x != hostname, parts))
                if not parts[1:]:
                    continue
                line = ' '.join(['\t'.join(parts), comment])
            ret.append((line, parts, comment))
        self.entries = ret
        self.write()
        self.output()

    def _parse(self):
        '''
        Parse the files into entries.
        '''
        self.entries = []
        fd = sys.stdin if self.filename == '-' else open(self.filename)
        for line in fd.readlines():
            self.entries.append(parse_line(line))

    def output(self, fd=None):
        if fd is None:
            fd = sys.stdout
        fd.write('\n'.join(map(lambda x: x[0].strip(), self.entries)))
        fd.write('\n')

    def write(self):
        if self.filename != '-':
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


def parse_cmdline():
    '''
    Parse cmd line arguments and returns a dictionary
    with its parsed values
    '''
    parser = argparse.ArgumentParser(
        prog='hostsed',
        description='A hosts file editing tool for command line shell')

    subparsers = parser.add_subparsers(dest='name')

    add_parser = subparsers.add_parser(
        name='add',
        help='Add entry IPADDRESS HOSTNAME1 [HOSTNAME2 ...]'
    )
    add_parser.add_argument('add',
                            type=str,
                            metavar='IPADDRESS_OR_HOSTNAME',
                            nargs='+')

    # subparser does not support aliasing
    del_opts = ['del', 'rm', 'delete', 'remove']
    for do in del_opts:
        del_parser = subparsers.add_parser(
            name=do,
            help='Delete an IPADDRESS HOSTNAME entry',
        )
        del_parser.add_argument(do, nargs=2, metavar='IPADDRESS_OR_HOSTNAME',)

    drop_parser = subparsers.add_parser(
        name='drop',
        help='Drop a lines containing an IP_OR_HOSTNAME entry'
    )
    drop_parser.add_argument('drop', nargs=1, metavar='IPADDRESS_OR_HOSTNAME')

    docker_parser = subparsers.add_parser(
        name='docker',
        help='Show docker cointainer IP address of the given name'
    )
    docker_parser.add_argument(
        'docker',
        help='Name of the Container to get IP address from',
        metavar='CONTAINER',
        type=str,
        nargs=1
    )

    parser.add_argument("-f", "--file",
                        default="/etc/hosts",
                        help="The location of hosts file, default /etc/hosts, - for reading from stdin",
                        type=str)
    dparser = vars(parser.parse_args())

    # normalize keys for del and its aliases:
    name = dparser.get('name')
    if name in del_opts:
        dparser['name'] = 'del'
        dparser['del'] = dparser.get(name)
    return dparser


def main():
    args = parse_cmdline()
    f_name = args.get('name')
    he = HostEditor(filename=args.get('file'))
    funcs = {
        'add': he.add,
        'del': he.delete,
        'drop': he.drop,
        'docker': he.output_docker_ip
    }
    try:
        if not args.get(f_name):
            he.output()
        else:
            funcs.get(f_name)(*args.get(f_name))
    except Exception as e:
        fd = sys.stdout
        fd.write('ERROR: {} \n'.format(e))

if __name__ == '__main__':
    main()
