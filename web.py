#!/usr/bin/env python3


from flask import Flask, render_template, request, jsonify
import random, json, config, wayfinder as wf, networkx as nx

app = Flask(__name__)

@app.route("/")
def output():
    return render_template("input.html")

@app.route('/receiver', methods = ['POST'])
def worker():

    data = request.get_json()

    type = wf.RouteType.UNDEF

    if data["pathing"] == "shortest":
        type = wf.RouteType.SHORTEST

    if data["pathing"] == "safest":
        type = wf.RouteType.SAFEST

    if data["pathing"] == "insecure":
        type = wf.RouteType.INSECURE

    (G, db) = wf.load_universe(config.UNIVERSE_JSON, config.SIGGY_DEFAULT_CHAINMAP)

    src = wf.name_to_id(db, data["start"])
    dest =  wf.name_to_id(db, data["end"])
    avoids = [];

    if data["avoid"][0] != "":
        avoids = list(map(lambda x : wf.name_to_id(db, x), data["avoid"]))

    G = wf.modify_graph(G, avoids, type, data["eol"], data["crit"], db)

    try:
        route = nx.shortest_path(G, src, dest, "weight")
    except nx.exception.NetworkXNoPath as e:
        return jsonify([{"Error":"No Path"}])

    res = []

    for id in route:
        system = db[id]
        temp = {}
        temp["name"] = system["name"]
        temp["region"] = system["region"]
        temp["security"] = "%.2f" % system["security"]
        res.append(temp)

    return jsonify(res)

if __name__ == "__main__":
    app.run("0.0.0.0", "5010")
