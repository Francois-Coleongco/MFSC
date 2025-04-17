This is just a little something to play around with sockets in cpp. since we aren't doing much cpp in uni atm i figured i'd do some noww.

we'll see if i'll build something bigger but at the moment i'm just having fun :)

you can hook this up with tailscale. have a little piece of hardware running the server, then people who have your software can connect to the server and chat with each other over encrypted terminal based chatting


todo:

need a way to keep track of users. make a sql db of users and passwords ----> the data will contain a username and a password. that is it.

the separate auth program will serve to generate the hash and send it to the db. which i will join together into one binary at the end.

so in order to communicate on the port 8080 of the server, the user must log in first.

sending credentials will be done over an encrypted connection, then further communications will be done with the same keys (on the condition of a successful login)



dependencies:

sqlite33 libsqlite3-dev libsodium-dev

must therefore build with respective linking

g++ auth.cpp -l sqlite3 -lsodium
