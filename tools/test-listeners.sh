#!/bin/bash

# Define the ports you want to test (change these as needed)
PORTS=(10001 10002 10003 10004 10005 10006 10007 10008 10009 10010)
PID_FILE="/tmp/socat_test_pids"

case "$1" in
    start)
        echo "Starting listeners on ports: ${PORTS[*]}"
        > "$PID_FILE" # Clear the file first
        
        for port in "${PORTS[@]}"; do
            # -l = listen, reuseaddr prevents 'Address already in use' errors if you restart quickly
            # fork handles multiple connections simultaneously
            # EXEC:"cat",pty,stderr creates an echo server (sends back what you send)
            socat TCP-LISTEN:${port},reuseaddr,fork EXEC:"cat",pty,stderr &
            
            # Save the PID of this specific listener to our file
            echo $! >> "$PID_FILE"
        done
        ;;
    stop)
        if [ -f "$PID_FILE" ]; then
            while read pid; do
                kill "$pid" 2>/dev/null
            done < "$PID_FILE"
            
            rm "$PID_FILE"
            echo "Listeners stopped."
        else
            echo "No listeners running (or PID file missing)."
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac
