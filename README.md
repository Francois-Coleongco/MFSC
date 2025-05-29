# Encrypted Multithreaded File Server & Client

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

just default c++ 17 standard works

must therefore build with respective linking (there is a build bash script that builds both the server and client ./build_atsic which builds it it into the ./test_build/ directory) i honestly had an acronym for atsic but i forgot what it meant so... whoops.

## todo:

read from file system

key rotation (need to halt all communications to prevent data loss from missing matching keys)
