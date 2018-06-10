#!/usr/bin/env python3

import json
import getopt, sys
import pprint
import networkx as nx
import urllib.request
from enum import Enum

class RouteType(Enum):
    UNDEF = 0
    SHORTEST = 1
    SAFEST = 2
    INSECURE = 3

def loadUniverse(map_file):
    json_data = open(map_file).read()
    data = json.loads(json_data)
    G = nx.Graph()
    db = {}
    for system in data["solarSystems"]:
        G.add_node(system["id"])
        db[system["id"]] = system
    for gate in data["jumps"]:
        G.add_edge(gate["from"], gate["to"])
        
    request = req = urllib.request.Request(
            "https://www.eve-scout.com/api/wormholes",
            data=None,
            headers={'User-Agent': 'RouteFinder v0.1b'}
        )
    contents = urllib.request.urlopen(req).read().decode('utf-8')
    data = json.loads(contents)

    for info in data:
        if info["type"] != "wormhole":
            continue
        if info["status"] != "scanned":
            continue
        eol = False
        if info["wormholeEol"] == "critical":
            eol = True
        G.add_edge(info["sourceSolarSystem"]["id"], info["destinationSolarSystem"]["id"], eol=eol, mass = info["wormholeMass"])
    return (G, db)

def modifyGraph(G, avoids, type, allowEol, allowCrit):
    G.remove_nodes_from(avoids)
    if type == RouteType.SAFEST:
        for edge in G.edges():
            if not isHighSec(db, edge[0]) or not isHighSec(db, edge[1]):
                G[edge[0]][edge[1]]['weight'] = 5000
            else:
                G[edge[0]][edge[1]]['weight'] = 1
    elif type == RouteType.INSECURE:
        for edge in G.edges():
            if isHighSec(db, edge[0]) or isHighSec(db, edge[1]):
                G[edge[0]][edge[1]]['weight'] = 5000
            else:
                G[edge[0]][edge[1]]['weight'] = 1
    else:
        for edge in G.edges():
            if isHighSec(db, edge[0]) and isHighSec(db, edge[1]):
                G[edge[0]][edge[1]]['weight'] = 1
            elif isHorW(db, edge[0]) and isHorW(db, edge[1]):
                G[edge[0]][edge[1]]['weight'] = 1.001
            elif isNullSec(db, edge[0]) or isNullSec(db, edge[1]):
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

def nameToId(db, name):
    for id, system in db.items():
        if system["name"] == name:
            return id
    print("No such system: %s" % name)
    exit(3)

def isHighSec(db, id):
    return db[id]["security"] >= 0.45

def isLowSec(db, id):
    return db[id]["security"] >= 0.0 and db[id]["security"] < 0.45

def isNullSec(db, id):
    return db[id]["security"] < 0.0 and id < 31000000

def isWspace(db, id):
    return id > 31000000

def isHorW(db, id):
    return isHighSec(db, id) or isWspace(db, id)


def usage():
        print("Usage: %s <From> <To> [Avoid ...]")
        
if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()
        exit(1)
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hec", ["shortest", "safest", "insecure", "allow-eol", "allow-crit"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(str(err))  # will print something like "option -a not recognized"
        usage()
        exit(2)

    allowEol = False
    allowCrit = False
    type = RouteType.UNDEF
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
        elif o == "-e" or o == "--allow-crit":
            allowCrit = True
        else:
            assert False, "unhandled option"

    if type == RouteType.UNDEF:
        type = RouteType.SHORTEST

    (G, db) = loadUniverse("universe-pretty.json")
    src = nameToId(db, args[0])
    dest = nameToId(db, args[1])
    avoids = list(map(lambda x : nameToId(db, x), args[2:]))
    desc = "Generating %s route from %s to %s" % (type, args[0], args[1])
    if len(avoids) > 0:
        desc += ", avoiding " + ", ".join(args[2:])
    print(desc)
    G = modifyGraph(G, avoids, type, allowEol, allowCrit)
    route = nx.shortest_path(G, src, dest, "weight")
    i = 0
    for id in route:
        system = db[id]
        print("%d : %s %s %.2f" % (i, system["name"], system["region"], system["security"]))
        i+=1
