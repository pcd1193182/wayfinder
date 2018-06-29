# Wayfinder

## Description
Wayfinder is (currently) a python script that can find the shortest path between two points in the eve universe, using a map generated from the Eve SDE, your current siggy chainmap, and eve-scout data.  It requires python3.

## Future work
The end goal for this tool is to provide a way for pilots to find their way using a convenient web UI, rather than having to run it on the command line. Corporations could deploy their own copy, pointing to their own siggy data.  Other possible features include:
* Using your current location, fetched from ESI, to route you
* Updating your in-game waypoints to allow easier travel
* Using ESI's current-ship endpoint to determine what wormholes you can traverse

## Dependencies
This project takes in a json file describing the Eve universe generated by a slightly modified version of https://github.com/mickdekkers/eve-map-json/ ; the only modification is to remove the filtering of wormhole and other special systems.

## Usage
Place the json file produced by eve-map-json in the root directory, and then run wayfinder.py.  Also fill out the siggy config data in `config.py` if you want to import your own wormhole maps from siggy.

Example usage:
`./wayfinder.py Jita Amarr`

The first argument is the starting location; the second is the destination. After that, a list of systems to avoid my be provided; if the destination cannot be reached without travelling through them, no route will be given.  Several arguments are available:

There is now a web component, to start up the server, simply run web.py:
`./web.py`

A basic webpage will be served to your hosting IP address, and can be accessed
on the same machine by opening a browser and going to 0.0.0.0:5010. Other
machines on the same network can access the page by going to your IP address at
port 5000. For example, if your IP address is 1.2.3.4, the webpage could be
accessed on another machine by opening a browser and going to 1.2.3.4:5010,
assuming there are no firewalls in the way.

### -h
Presents the usage information

### -c, --allow-crit
Allows the usage of crit wormholes in the route calculation. By default these wormholes are ignored.

### -e, --allow-eol
Allows the usage of EOL wormholes in the route calculation. By default these wormholes are ignored.

### --shortest, --safest, --insecure
Defines the routing algorithm to be used. Only one may be specified, and only once. Shortest tries to find the shortest path, no matter what (though it will prefer higher-security and wormhole systems when the routes are the same number of jumps). Secure tries to stick to high security space as much as possible. Insecure attempts to avoid highsec whenever possible.
