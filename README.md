# Encrypted File Server & Client

## what is this?

I want to make my own cloud storage essentially via an encrypted file server on some piece of hardware that i hook up with tailscale. (I'd rather not expose my home network to the internet thank you very much xd)

## dependencies:

ubuntu/ubuntu based (sorry idk if these pkgs are on debian):

```
sudo apt install sqlite3 libsqlite3-dev libsodium-dev
```

fedora (what i'm using rn):
```
sudo dnf sqlite3 libsqlite3-dev libsodium-dev
```

## building
must therefore build with respective linking (there is a build script that builds both the server and client ./build_atsic) i honestly had an acronym for atsic but i forgot what it meant so... whoops.

## why
This is just a little something to play around with sockets in cpp. since we aren't doing much cpp in uni atm i figured i'd do some noww.

we'll see if i'll build something bigger but at the moment i'm just having fun :) (update, we are not just having fun it blew up into a big project TwT)

## todo:

need a way to keep track of users. make a sql db of users and passwords ----> the data will contain a username and a password. that is it.

the separate auth program will serve to generate the hash and send it to the db. which i will join together into one binary at the end.

so in order to communicate on the port 8080 of the server, the user must log in first.

sending credentials will be done over an encrypted connection, then further communications will be done with the same keys (on the condition of a successful login)

