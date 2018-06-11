#!/usr/bin/env python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Copyright (c) 2018 by Paul Dagnelie.

import json
import getopt, sys
import pprint
import networkx as nx
import urllib.request
from enum import Enum

import config
import siggy

class RouteType(Enum):
    UNDEF = 0
    SHORTEST = 1
    SAFEST = 2
    INSECURE = 3

def load_universe(map_file, chainmap_id):
    json_data = open(map_file).read()
    data = json.loads(json_data)
    G = nx.Graph()
    db = {}
    for system in data["solarSystems"]:
        G.add_node(system["id"])
        db[system["id"]] = system
    for gate in data["jumps"]:
        G.add_edge(gate["from"], gate["to"])

    # Load data from eve-scout
    request = req = urllib.request.Request(
            "https://www.eve-scout.com/api/wormholes",
            data=None,
            headers={'User-Agent': 'RouteFinder v0.1b'}
        )
    contents = urllib.request.urlopen(req).read().decode('utf-8')
    data = json.loads(contents)

    for wormhole in data:
        if wormhole["type"] != "wormhole":
            continue
        if wormhole["status"] != "scanned":
            continue
        eol = False
        if wormhole["wormholeEol"] == "critical":
            eol = True
        G.add_edge(wormhole["sourceSolarSystem"]["id"], wormhole["destinationSolarSystem"]["id"],
                   eol=eol, mass = wormhole["wormholeMass"])

    # Load siggy data if we have siggy configured
    if len(config.SIGGY_KEYID) > 0:
        data = json.loads(siggy.get_chain(chainmap_id))
        for wormhole in data["wormholes"]:
            # Note that we can't support crit detection from siggy until mass status is added to the API.
            # We can however treat frigate holes as critical, as an approximation
            mass = "stable"
            if wormhole["frigate_sized"]:
                crit = "critical"
            eol = False
            if wormhole["eol"] == 1:
                eol = True
            G.add_edge(wormhole["from_system_id"], wormhole["to_system_id"], eol = eol, mass = mass)
    
    return (G, db)

def modify_graph(G, avoids, type, allowEol, allowCrit):
    G.remove_nodes_from(avoids)
    if type == RouteType.SAFEST:
        for edge in G.edges():
            if not is_high_sec(db, edge[0]) or not is_high_sec(db, edge[1]):
                G[edge[0]][edge[1]]['weight'] = 5000
            else:
                G[edge[0]][edge[1]]['weight'] = 1
    elif type == RouteType.INSECURE:
        for edge in G.edges():
            if is_high_sec(db, edge[0]) or is_high_sec(db, edge[1]):
                G[edge[0]][edge[1]]['weight'] = 5000
            else:
                G[edge[0]][edge[1]]['weight'] = 1
    else:
        for edge in G.edges():
            if is_high_sec(db, edge[0]) and is_high_sec(db, edge[1]):
                G[edge[0]][edge[1]]['weight'] = 1
            elif is_h_or_w(db, edge[0]) and is_h_or_w(db, edge[1]):
                G[edge[0]][edge[1]]['weight'] = 1.001
            elif is_null_sec(db, edge[0]) or is_null_sec(db, edge[1]):
                G[edge[0]][edge[1]]['weight'] = 1.003
            else:
                G[edge[0]][edge[1]]['weight'] = 1.002
    if not allowEol:
        eols = []
        for edge in G.edges():
            if "eol" in G[edge[0]][edge[1]] and G[edge[0]][edge[1]]["eol"]:
                eols.append(edge)
        G.remove_edges_from(eols)
    if not allowCrit:
        crits = []
        for edge in G.edges():
            if "mass" in G[edge[0]][edge[1]] and G[edge[0]][edge[1]]["mass"] == "critical":
                crits.append(edge)
        G.remove_edges_from(crits)
    return G

def name_to_id(db, name):
    for id, system in db.items():
        if system["name"] == name:
            return id
    print("No such system: %s" % name)
    exit(3)

def is_high_sec(db, id):
    return db[id]["security"] >= 0.45

def is_low_sec(db, id):
    return db[id]["security"] >= 0.0 and db[id]["security"] < 0.45

def is_null_sec(db, id):
    return db[id]["security"] < 0.0 and id < 31000000

def is_wspace(db, id):
    return id > 31000000

def is_h_or_w(db, id):
    return is_high_sec(db, id) or is_wspace(db, id)


def usage():
        print("Usage: %s <From> <To> [Avoid ...]")
        
if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hec", ["shortest", "safest", "insecure", "allow-eol", "allow-crit", "chain=", "maps"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(str(err))  # will print something like "option -a not recognized"
        usage()
        exit(2)

    allowEol = False
    allowCrit = False
    type = RouteType.UNDEF
    chainmap_id = config.SIGGY_DEFAULT_CHAINMAP
    for o,a in opts:
        if o == "-h":
            usage()
            exit(0)
        elif o == "--shortest":
            if type != RouteType.UNDEF:
                print("Multiple route types specified")
                exit(3)
            type = RouteType.SHORTEST
        elif o == "--safest":
            if type != RouteType.UNDEF:
                print("Multiple route types specified")
                exit(3)
            type = RouteType.SAFEST
        elif o == "--insecure":
            if type != RouteType.UNDEF:
                print("Multiple route types specified")
                exit(3)
            type = RouteType.INSECURE
        elif o == "-e" or o == "--allow-eol":
            allowEol = True
        elif o == "-c" or o == "--allow-crit":
            allowCrit = True
        elif o == "--chain":
            chainmap_id = a;
        elif o == "--maps":
            print(siggy.get_chainmaps())
            exit
        else:
            assert False, "unhandled option"

    if len(args) < 2:
        usage()
        exit(1)
    
    if type == RouteType.UNDEF:
        type = RouteType.SHORTEST

    (G, db) = load_universe(config.UNIVERSE_JSON, chainmap_id)
    src = name_to_id(db, args[0])
    dest = name_to_id(db, args[1])
    avoids = list(map(lambda x : name_to_id(db, x), args[2:]))
    desc = "Generating %s route from %s to %s, %s eol connections and %s crit holes" % (type,
        args[0], args[1], "allowing" if allowEol else "ignoring", "allowing" if allowCrit else "ignoring")
    if len(avoids) > 0:
        desc += ", avoiding " + ", ".join(args[2:])
    print(desc)
    G = modify_graph(G, avoids, type, allowEol, allowCrit)
    try:
        route = nx.shortest_path(G, src, dest, "weight")
    except nx.exception.NetworkXNoPath as e:
        print("No path to " + args[0] + " from " + args[1])
        exit(5)
    i = 0
    for id in route:
        system = db[id]
        print("%d : %s %s %.2f" % (i, system["name"], system["region"], system["security"]))
        i+=1
