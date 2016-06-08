# hostsed -- A tiny hosts file command line edit tool

hostsed is a simple python tool for editing hosts file(/etc/hosts), you can add or delete a DNS entry via command line shell(e.x. bash).


Usage:

```
# Add an entry
sudo hostsed add <ip address> <hostname1> <hostname2> ...

Example:
sudo hostsed add 192.168.1.1 gateway
sudo hostsed add 172.17.0.5 mongo-store-1 mysql-02

# Delete an entry
sudo hosted del <ip address> <hostname>
hosted remove 192.168.1.1 gateway
```
