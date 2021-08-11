# hostsed -- A tiny hosts file command line edit tool

hostsed is a simple python tool for editing hosts file(default /etc/hosts), you can add or delete a DNS entry via command line shell(e.x. bash). Editing hosts file with hostsed would be a more idemponent command line experience, i.e., add/del the same record won't result duplicated or missing entries in the hosts file. hostsed will check the validity ip address for both IPV4 and IPV6.

## Install
You may install hostsed via pip. Python3 is preferred:

```
sudo pip3 install hostsed
```

Or on system default pip command:

```
sudo pip install hostsed
```

## Usage

### Display the hosts file content

    sudo hostsed
    # specify a location other than /etc/hosts
    hostsed --file hosts.example

### Add an entry

    sudo hostsed add <ip address> <hostname1> <hostname2> ...

Example:

    sudo hostsed add 192.168.1.1 gateway
    sudo hostsed add 172.17.0.5 mongo-store-1 mysql-02
    hostsed --file hosts.exmaple add 127.0.0.1 valarmorghulis.io

### Delete an entry
rm/delete/remove are all alias for del:

    sudo hostsed del <ip address> <hostname>

Example:

    sudo hostsed remove 192.168.1.1 gateway
    hostsed --file hosts.exmaple rm ::1 localhost

### Drop lines with specified ip or hostname

    sudo hostsed drop <ip or hostname>

Example:

    sudo hostsed drop 192.168.1.1
    sudo hostsed drop www.example.com
    hostsed --file hosts.exmaple drop ::1

### Get the ip address of a docker container

    sudo hostsed docker <docker-container-name>

## Acknowledgement

Thanks for @noahfx provide some awesome improve for hostsed.