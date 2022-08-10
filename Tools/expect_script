#!/usr/bin/expect

#trap sigwinch and pass it to the child we spawned
#this allows the gnome-terminal window to be resized
trap {
 set rows [stty rows]
 set cols [stty columns]
 stty rows $rows columns $cols < $spawn_out(slave,name)
} WINCH

set arg1 [lindex $argv 0]

# Get a Bash shell
spawn -noecho bash

# Wait for a prompt
expect "$ "

# Type something
send $arg1

# Hand over control to the user
interact

exit
