gdb -quiet -ex "set confirm off"\
    -ex "handle SIGTRAP nostop noprint pass" \
    -ex "handle SIGINT nostop noprint pass" \
    -ex "handle SIGPIPE nostop noprint pass" \
    -ex "handle SIGSEGV stop print pass" \
    -ex "handle SIGABRT stop print pass" \
    -ex "target remote | vgdb" \
    -ex "continue"
