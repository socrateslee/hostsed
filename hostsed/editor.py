'''
Utilities for adding or deleting entries on hosts file
as /etc/hosts.
'''
import os
import sys
import json
import copy
import subprocess
import socket
import argparse


def get_default_host_location(platform=None):
    '''
    Get the default location of hosts file.
    '''
    if not platform:
        platform = sys.platform
    if platform == 'win32':
        return 'C:\\Windows\\System32\\drivers\\etc\\hosts'
    else:
        return '/etc/hosts'


def get_file_content(filename):
    '''
    Get the content of a file.
    '''
    if filename == '-':
        return sys.stdin.read()
    else:
        with open(filename, 'r') as f:
            return f.read()


def get_output_fd(filename, dryrun=False):
    '''
    Get the output file descriptor of a file.
    '''
    if filename == '-' or dryrun:
        return sys.stdout
    else:
        fd = open(filename, 'w')
        return fd


def is_valid_ip_address(ip):
    '''
    Check whether an ip address is valid, both for ipv4
    and ipv6.
    '''
    try:
        socket.inet_pton(socket.AF_INET, ip) # IPv4 check
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip) # IPv6 check
            return True
        except socket.error:
            return False


def parse_line(line):
    parts_combine, sep, comment = line.partition('#')
    comment = sep + comment
    parts = list(map(lambda x: x.strip(), parts_combine.split()))
    if parts:
        return (line, parts, comment)
    else:
        return (line, None, comment)


def chk_user_permissions(filename):
    '''
    Check if current user has sufficient permissions to
    edit hosts file.
    Raise an exception if user is invalid
    '''
    if filename != '-' and not os.access(self.filename, os.W_OK):
        msg = 'User does not have sufficient permissions, are you super user?'
        raise Exception(msg)
    return


class HostEditor(object):
    def __init__(self, content, platform=None):
        if not platform:
            self.platform = sys.platform
        self.content = content
        self._parse()

    def add(self, ip, *hostnames, platform=None):
        '''
        Add an entry to hosts file.
        '''
        if not is_valid_ip_address(ip):
            raise Exception("IP %s is not valid." % ip)

        if not self.entries:
            return
        ret = []
        added = False
        if not self.entries:
            return

        if self.platform != 'win32':
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
        else:
            curr_hostnames = copy.copy(hostnames)
            for (line, parts, comment) in self.entries:
                if parts and parts[0] == ip and not added:
                    curr_hostnames = [
                        hostname for hostname in curr_hostnames
                        if hostname not in parts[1:]
                    ]
                ret.append((line, parts, comment))
            if curr_hostnames:
                for hostname in curr_hostnames:
                    parts = [ip, hostname]
                    line = '\t'.join(parts)
                    ret.append((line, parts, ''))
        self.entries = ret

    def drop(self, ip_or_hostname):
        '''
        Drop lines with specified ip or hostname from hosts file.
        '''
        ret = []
        for (line, parts, comment) in self.entries:
            if parts and ip_or_hostname in parts:
                continue
            ret.append((line, parts, comment))
        self.entries = ret

    def delete(self, *args):
        '''
        Delete host from the lines with (ip, hostname) tuple from hosts file.
        If ip is None, match only hostname and delete matched entry
        '''
        if len(args) == 2:
            ip, hostname = args
        elif len(args) == 1:
            ip = None
            hostname = args[0]
        else:
            raise Exception("Invalid arguments")
        ret = []
        for (line, parts, comment) in self.entries:
            if parts:
                if ip is None:
                    if hostname in parts[1:]: # Check if hostname is in hostnames (parts[1:])
                        parts = list(filter(lambda x: x != hostname, parts))
                        if not parts[1:]: # if no hostnames left, remove the whole line
                            continue
                        line = ' '.join(['\t'.join(parts), comment])
                elif parts[0] == ip: # if ip is not None, check ip and hostname
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
        for line in self.content.splitlines():
            self.entries.append(parse_line(line))

    def render(self):
        '''
        Render the entries into a string.
        '''
        sep = os.linesep
        return sep.join(map(lambda x: x[0].strip(), self.entries))

    def output(self, fd=None):
        if fd is None:
            fd = sys.stdout
        fd.write(self.render())
        fd.write(os.linesep)


def docker_ip(container):
    '''
    Get the ip address of a docker container.
    '''
    proc = subprocess.Popen("docker inspect %s" % container,
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if proc.returncode == 0:
        ret = json.loads(stdout.decode('utf-8'))
        ip = ret[0]['NetworkSettings']['IPAddress']
        return ip


class OneOrTwo(argparse.Action):
    '''
    Action to parse one or two arguments.
    '''
    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, nargs=None):
        if 1 <= len(values) <= 2:
            setattr(namespace, self.dest, values)
        else:
            raise ValueError(
                'argument %s: expected 1 or 2 values' % self.dest)

    def format_usage(self):
        return 'IPADDRESS HOSTNAME\nHOSTNAME'


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
    del_aliases = ['rm', 'delete', 'remove']
    del_parser = subparsers.add_parser(
        name='del',
        help='Delete an (IPADDRESS, HOSTNAME) pair or a HOSTNAME occurence',
        aliases=del_aliases
    )
    del_parser.add_argument('del',
        nargs='+',
        metavar='(IPADDRESS HOSTNAME)|HOSTNAME',
        action=OneOrTwo,
        help='Delete either:\n- A specific (IPADDRESS, HOSTNAME) pair\n- All entries containing HOSTNAME')

    drop_parser = subparsers.add_parser(
        name='drop',
        help='Drop a lines containing an IP_OR_HOSTNAME entry'
    )
    drop_parser.add_argument('drop', nargs=1, metavar='IPADDRESS_OR_HOSTNAME')

    docker_parser = subparsers.add_parser(
        name='docker',
        help='Show docker container IP address of the given name'
    )
    docker_parser.add_argument(
        'docker',
        help='Name of the Container to get IP address from',
        metavar='CONTAINER',
        type=str,
        nargs=1
    )

    parser.add_argument("-f", "--file",
                        default="",
                        help="The location of hosts file, default /etc/hosts, - for reading from stdin",
                        type=str)

    parser.add_argument("--platform",
                        default="",
                        help="The platform to use, 'win32' for Windows, default is the current platform.",
                        type=str)

    parser.add_argument("--dryrun",
                        default=False,
                        action='store_true',
                        help="Print the result of the operation without modifying the hosts file.")

    args = vars(parser.parse_args())
    if args.get('name') in del_aliases:
        args['name'] = 'del'
    return args


def should_check_permissions(filename):
    '''
    Check whether the user has permissions to edit the file.
    '''
    if os.path.exists(filename):
        return os.access(filename, os.W_OK)
    else:
        return False

HOSTS_FUNCS = [
    'add',
    'del',
    'drop',
]

DOCKER_FUNCS = [
    'docker',
]

FUNCS = {
    'add': HostEditor.add,
    'del': HostEditor.delete,
    'drop': HostEditor.drop,
    'docker': docker_ip
}

def main():
    args = parse_cmdline()
    func_name = args.get('name')
    try:
        if func_name in DOCKER_FUNCS:
            func = FUNCS.get(func_name)
            print(func(*args.get(func_name)))
        elif func_name in HOSTS_FUNCS:
            func = FUNCS.get(func_name)
            filename = args.get('file') or get_default_host_location(platform=args.get('platform'))
            content = get_file_content(filename)
            he = HostEditor(content, platform=args.get('platform'))
            func(he, *args.get(func_name))
            with get_output_fd(filename, dryrun=args.get('dryrun')) as fd:
                he.output(fd)
        elif not func_name:
            filename = args.get('file') or get_default_host_location(platform=args.get('platform'))
            content = get_file_content(filename)
            he = HostEditor(content, platform=args.get('platform'))
            he.output()
        else:
            raise Exception("Invalid function name: %s" % func_name)
    except Exception as e:
        fd = sys.stderr
        fd.write('ERROR: {} \n'.format(e))


if __name__ == '__main__':
    main()
